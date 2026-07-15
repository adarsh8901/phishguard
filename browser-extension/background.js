importScripts('api_config.js', 'scan_result.js');

const { API_BASE_URL, SCAN_TIMEOUT_MS } = PhishGuardApi;
const { CACHE_SCHEMA_VERSION, normalizeUrl, normalizeScanResult, mergeScanResults } = PhishGuardResults;

const IGNORED_SCHEMES = [
  'chrome://',
  'edge://',
  'about:',
  'chrome-extension://',
  'moz-extension://',
  'file://',
  'view-source:',
  'data:',
  'blob:',
];
const TRUSTED_DOMAINS = [
  'google.com',
  'www.google.com',
  'accounts.google.com',
  'gstatic.com',
  'googleapis.com',
  'youtube.com',
  'github.com',
  'microsoft.com',
  'openai.com',
  'chatgpt.com',
];
const URL_CACHE_TTL_MS = 2 * 60 * 1000;
const scanCache = new Map();
const urlCache = new Map();
const pendingScans = new Map();
const bypassedTabs = new Set();
const browserWarnings = new Map();
let cachedBackendUrl = API_BASE_URL;
let backendUrlReady = null;

function configuredBackendUrl(value) {
  return API_BASE_URL;
}

function loadBackendUrl() {
  if (!backendUrlReady) {
    backendUrlReady = new Promise((resolve) => {
      chrome.storage.local.get(['pg_backendUrl'], (data) => {
        cachedBackendUrl = configuredBackendUrl(data.pg_backendUrl);
        if (data.pg_backendUrl !== API_BASE_URL) {
          chrome.storage.local.set({ pg_backendUrl: API_BASE_URL });
        }
        resolve(cachedBackendUrl);
      });
    });
  }
  return backendUrlReady;
}

loadBackendUrl();

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== 'local' || !changes.pg_backendUrl) return;
  cachedBackendUrl = API_BASE_URL;
});

function notify(details) {
  chrome.notifications.create('', {
    type: 'basic',
    iconUrl: 'icons/icon-128.png',
    title: `PhishGuard: ${details.title}`,
    message: details.message,
    priority: 2,
  });
}

function shouldScanUrl(url) {
  if (!url) return false;
  if (url.includes('warning.html')) return false;
  if (IGNORED_SCHEMES.some((scheme) => url.startsWith(scheme))) return false;
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
    if (hostname === 'localhost' || hostname === '127.0.0.1') return false;
    const backendOrigin = new URL(cachedBackendUrl).origin;
    if (parsed.origin === backendOrigin) return false;
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function isHttpUrl(url) {
  return typeof url === 'string' && (url.startsWith('http://') || url.startsWith('https://'));
}

function normalizedHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return '';
  }
}

function normalizedUrlKey(url) {
  return normalizeUrl(url);
}

function isTrustedHostname(hostname) {
  return TRUSTED_DOMAINS.some(
    (trusted) => hostname === trusted || hostname.endsWith(`.${trusted}`)
  );
}

function isMissingTabError(error) {
  const message = String(error?.message || error || '');
  return message.includes('No tab with id') || message.includes('Invalid tab ID');
}

async function setThreatBadge(tabId, text, color) {
  if (!Number.isInteger(tabId) || !chrome.action) return;
  try {
    await chrome.action.setBadgeText({ tabId, text });
    if (text && color) {
      await chrome.action.setBadgeBackgroundColor({ tabId, color });
    }
  } catch (error) {
    if (!isMissingTabError(error)) {
      console.warn('[PhishGuard] Failed to update tab badge:', error);
    }
  }
}

async function safelyUpdateTab(tabId, updateProperties) {
  if (!Number.isInteger(tabId)) return false;
  try {
    await chrome.tabs.update(tabId, updateProperties);
    return true;
  } catch (error) {
    if (!isMissingTabError(error)) {
      console.warn('[PhishGuard] Failed to update tab:', error);
    }
    return false;
  }
}

function unknownScanResult(url, error) {
  return normalizeScanResult({ url, success: false, error: error?.message || String(error) }, url, 'backend');
}

function browserWarningResult(url, error) {
  return normalizeScanResult({
    url, status: 'DANGEROUS', risk_score: 100, confidence: 100,
    recommendation: 'Chrome blocked or warned about this navigation. Do not continue to this site.',
    reasons: ['Browser warning detected'], success: true, error: null,
  }, url, 'browser_warning');
}

function isBrowserSecurityError(error) {
  return /SAFE_BROWSING|BLOCKED_BY_CLIENT|BLOCKED_BY_RESPONSE|CERT_|SSL_|MALWARE|PHISH/i.test(String(error || ''));
}

function pruneUrlCache(now = Date.now()) {
  for (const [cachedUrl, entry] of urlCache.entries()) {
    if (!entry || now - entry.createdAt >= URL_CACHE_TTL_MS) {
      urlCache.delete(cachedUrl);
    }
  }
}

function processScanResult(result, url, tabId, source) {
  const cacheKey = normalizedUrlKey(url);
  const normalized = normalizeScanResult(result, url, source === 'browser-warning' || source === 'browser_warning' ? 'browser_warning' : source === 'cache' ? 'cache' : 'backend');
  const preservedWarning = browserWarnings.get(cacheKey);
  result = mergeScanResults(preservedWarning, normalized);
  if (!result?.success || result.url !== cacheKey) return result;

  const hostname = normalizedHostname(result.url || url);
  const score = result.risk_score;
  const verdict = result.status;
  const browserWarning = result.source === 'browser_warning';
  const shouldBlock = !browserWarning && verdict === 'DANGEROUS';
  const scanRecord = {
    url: result.url || url,
    domain: result.domain || new URL(url).hostname,
    risk_score: score,
    risk_classification: verdict,
    is_phishing: verdict === 'DANGEROUS',
    confidence: result.confidence,
    created_at: new Date().toISOString(),
    source: result.source,
    verdict,
    detection_sources: result.detection_sources || [source || result.source || 'extension-scan'],
  };

  urlCache.set(cacheKey, { schemaVersion: CACHE_SCHEMA_VERSION, createdAt: Date.now(), result });
  chrome.storage.local.set({ lastScan: result, scanCacheSchemaVersion: CACHE_SCHEMA_VERSION });
  if (Number.isInteger(tabId)) scanCache.set(tabId, cacheKey);

  chrome.storage.local.get(['scanHistory'], (data) => {
    const history = Array.isArray(data.scanHistory) ? data.scanHistory : [];
    history.unshift(scanRecord);
    chrome.storage.local.set({ scanHistory: history.slice(0, 50) });
  });

  if (browserWarning) {
    setThreatBadge(tabId, '!', '#b91c1c');
  } else if (shouldBlock) {
    setThreatBadge(tabId, '×', '#b91c1c');
    notify({
      title: 'Malicious site detected',
      message: `${scanRecord.domain} is flagged ${verdict}`,
    });
    const warningPage = `${chrome.runtime.getURL('warning.html')}?blockedUrl=${encodeURIComponent(url)}`;
    if (Number.isInteger(tabId)) {
      safelyUpdateTab(tabId, { url: warningPage });
    }
  } else if (verdict === 'SUSPICIOUS') {
    setThreatBadge(tabId, '!', '#d97706');
  } else {
    setThreatBadge(tabId, '', null);
  }

  return result;
}

async function requestScan(url, tabId) {
  await loadBackendUrl();
  if (!shouldScanUrl(url) || !isHttpUrl(url)) {
    return null;
  }
  if (tabId && bypassedTabs.has(tabId)) return;
  if (tabId && scanCache.get(tabId) === normalizedUrlKey(url)) return;

  pruneUrlCache();

  const cacheKey = normalizedUrlKey(url);
  const cachedResult = urlCache.get(cacheKey);
  if (cachedResult && cachedResult.schemaVersion === CACHE_SCHEMA_VERSION
      && Date.now() - cachedResult.createdAt < URL_CACHE_TTL_MS) {
    processScanResult(cachedResult.result, url, tabId, 'cache');
    return;
  }

  if (pendingScans.has(cacheKey)) return pendingScans.get(cacheKey);

  const scanPromise = performScan(url, tabId);
  pendingScans.set(cacheKey, scanPromise);
  try {
    return await scanPromise;
  } finally {
    pendingScans.delete(cacheKey);
  }
}

async function performScan(url, tabId) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);
  try {
    const response = await fetch(`${cachedBackendUrl}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, use_network: true }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error('Scan request failed');
    const result = await response.json();
    return processScanResult(result, url, tabId, 'backend');
  } catch (error) {
    const unknown = unknownScanResult(url, error);
    if (!browserWarnings.has(normalizedUrlKey(url))) setThreatBadge(tabId, '?', '#6b7280');
    return unknown;
  } finally {
    clearTimeout(timeoutId);
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message?.type || sender?.id !== chrome.runtime.id) return false;

  if (message.type === 'suspicious_form' && sender.tab?.id) {
    notify({
      title: 'Suspicious form detected',
      message: `Suspicious form found on ${message.url}`,
    });
    requestScan(message.url, sender.tab.id);
    sendResponse({ success: true });
    return false;
  }

  if (message.type === 'page_suspicious' && sender.tab?.id) {
    notify({
      title: 'Suspicious page activity',
      message: `Suspicious content detected on ${message.url}`,
    });
    requestScan(message.url, sender.tab.id);
    sendResponse({ success: true });
    return false;
  }

  if (message.type === 'bypass_warning' && sender.tab?.id) {
    bypassedTabs.add(sender.tab.id);
    setTimeout(() => bypassedTabs.delete(sender.tab.id), 60000);
    sendResponse({ success: true });
    return false;
  }
  sendResponse({ success: false, error: 'Unsupported message type' });
  return false;
});

chrome.tabs.onRemoved.addListener((tabId) => {
  scanCache.delete(tabId);
  bypassedTabs.delete(tabId);
});
chrome.tabs.onReplaced.addListener((_addedTabId, removedTabId) => scanCache.delete(removedTabId));

chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  await requestScan(details.url, details.tabId);
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  const qualifiers = details.transitionQualifiers || [];
  if (!qualifiers.includes('server_redirect') && !qualifiers.includes('client_redirect')) return;
  scanCache.delete(details.tabId);
  if (isHttpUrl(details.url)) requestScan(details.url, details.tabId);
});

chrome.webNavigation.onErrorOccurred.addListener((details) => {
  if (details.frameId !== 0 || !isHttpUrl(details.url)) return;
  const result = isBrowserSecurityError(details.error)
    ? browserWarningResult(details.url, details.error)
    : unknownScanResult(details.url, details.error);
  if (result.status === 'DANGEROUS') {
    browserWarnings.set(normalizedUrlKey(details.url), result);
    processScanResult(result, details.url, details.tabId, result.source);
  } else {
    setThreatBadge(details.tabId, '?', '#6b7280');
  }
});

chrome.downloads.onCreated.addListener((downloadItem) => {
  if (downloadItem?.url) {
    requestScan(downloadItem.url, null);
  }
});
