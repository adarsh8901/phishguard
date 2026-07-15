if (!globalThis.PhishGuardApi) {
  throw new Error('PhishGuardApi helper was not loaded');
}

if (!globalThis.PhishGuardResults) {
  throw new Error('PhishGuardResults helper was not loaded');
}

const { API_BASE_URL, HEALTH_TIMEOUT_MS, HEALTH_RETRY_DELAY_MS, SCAN_TIMEOUT_MS } = globalThis.PhishGuardApi;
const { CACHE_SCHEMA_VERSION, normalizeUrl, normalizeScanResult, mergeScanResults } = globalThis.PhishGuardResults;

let backendStatus = 'checking';
let scanStatus = 'idle';
let currentResult = null;
let initialized = false;

const elements = {
  backendStatus: document.querySelector('#backend-status'), siteStatus: document.querySelector('#site-status'),
  currentSite: document.querySelector('#current-site'), form: document.querySelector('#scan-form'),
  input: document.querySelector('#url-input'), button: document.querySelector('#scan-button'),
  error: document.querySelector('#form-error'), result: document.querySelector('#result'),
  score: document.querySelector('#risk-score'), recommendation: document.querySelector('#recommendation'),
  aiPrediction: document.querySelector('#ai-prediction'), aiConfidence: document.querySelector('#ai-confidence'),
  history: document.querySelector('#history-list'), refresh: document.querySelector('#refresh-history'),
};

for (const [name, element] of Object.entries(elements)) {
  if (!element) throw new Error(`Popup element was not found: ${name}`);
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const storageGet = (keys) => new Promise((resolve) => chrome.storage.local.get(keys, resolve));
const activeTab = () => new Promise((resolve) => chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => resolve(tabs[0])));

function escapeHtml(value) {
  const node = document.createElement('span'); node.textContent = String(value ?? ''); return node.innerHTML;
}

function setBackendStatus(status) {
  backendStatus = status;
  const text = { checking: 'Checking backend...', online: 'Backend online', offline: 'Backend offline' }[status];
  elements.backendStatus.textContent = text;
  elements.backendStatus.className = `backend ${status === 'checking' ? 'pending' : status}`;
}

function showResult(result, notice = '') {
  if (!result?.success) return;
  currentResult = result;
  elements.result.classList.remove('hidden');
  elements.score.textContent = `${Math.round(result.risk_score)}/100 · ${result.status}`;
  const recommendation = result.recommendation || 'Use caution and verify the address before sharing information.';
  elements.recommendation.textContent = notice ? `${recommendation} ${notice}` : recommendation;
  elements.aiPrediction.textContent = result.status === 'DANGEROUS' ? 'Potential phishing' : result.status === 'SUSPICIOUS' ? 'Suspicious' : 'Likely safe';
  elements.aiPrediction.className = result.status === 'DANGEROUS' ? 'danger' : result.status === 'SAFE' ? 'safe' : 'unknown';
  elements.aiConfidence.textContent = `${Math.round(result.confidence)}% confidence`;
  elements.siteStatus.textContent = result.status;
  elements.siteStatus.className = result.status === 'DANGEROUS' ? 'danger' : result.status === 'SUSPICIOUS' ? 'caution' : 'safe';
}

function classifyError(error, context) {
  if (error?.name === 'AbortError') {
    return { type: 'timeout', message: context === 'health' ? 'Backend health check timed out.' : 'Analysis timed out. Try again.', backendReachable: context !== 'health' && backendStatus === 'online' };
  }
  if (error?.kind === 'http') {
    return { type: 'http', message: error.status >= 500 ? 'Backend analysis failed.' : 'The scan request was rejected.', backendReachable: true };
  }
  if (error?.kind === 'invalid_response') {
    return { type: 'invalid_response', message: 'Analysis returned an invalid result.', backendReachable: true };
  }
  if (error?.kind === 'analysis') {
    return { type: 'analysis', message: 'Backend analysis failed.', backendReachable: true };
  }
  return { type: 'network', message: 'Backend connection unavailable.', backendReachable: false };
}

async function request(path, options, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, { ...options, signal: controller.signal });
    let data;
    try { data = await response.json(); }
    catch {
      if (!response.ok) throw Object.assign(new Error(`HTTP ${response.status}`), { kind: 'http', status: response.status });
      throw Object.assign(new Error('Malformed JSON'), { kind: 'invalid_response' });
    }
    if (!response.ok) throw Object.assign(new Error(data.error || `HTTP ${response.status}`), { kind: 'http', status: response.status, data });
    return data;
  } finally { clearTimeout(timeout); }
}

async function checkHealth() {
  let lastError;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const result = await request('/health', {}, HEALTH_TIMEOUT_MS);
      console.debug('Health check:', result);
      if (result?.status !== 'ok' || result?.service !== 'phishguard') throw Object.assign(new Error('Invalid health response'), { kind: 'invalid_response' });
      setBackendStatus('online'); return true;
    } catch (error) {
      lastError = error;
      if (attempt === 0) await delay(HEALTH_RETRY_DELAY_MS);
    }
  }
  console.error('Health check failed:', lastError);
  const classified = classifyError(lastError, 'health');
  setBackendStatus(classified.backendReachable ? 'online' : 'offline');
  return classified.backendReachable;
}

function showScanFailure(classified) {
  scanStatus = classified.type === 'network' ? 'unavailable' : 'failed';
  setBackendStatus(classified.backendReachable ? 'online' : 'offline');
  if (currentResult?.success) {
    const notice = currentResult.source === 'browser_warning'
      ? 'Backend analysis was unavailable. Browser warning result preserved.'
      : 'Latest backend check was unavailable.';
    showResult(currentResult, notice);
    return;
  }
  elements.siteStatus.textContent = classified.type === 'timeout' ? 'Analysis timed out' : 'Analysis unavailable';
  elements.siteStatus.className = 'unknown';
  elements.result.classList.remove('hidden');
  elements.score.textContent = 'Not available';
  elements.recommendation.textContent = classified.message;
  elements.aiPrediction.textContent = 'Scan unavailable';
  elements.aiPrediction.className = 'unknown';
  elements.aiConfidence.textContent = '';
}

async function scan(url) {
  if (scanStatus === 'scanning') return;
  scanStatus = 'scanning';
  elements.error.textContent = '';
  elements.button.disabled = true; elements.button.textContent = 'Scanning…';
  elements.siteStatus.textContent = 'Scanning…'; elements.siteStatus.className = 'unknown';
  console.debug('Scanning URL:', url);
  try {
    const data = await request('/predict', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url, use_network: true }),
    }, SCAN_TIMEOUT_MS);
    console.debug('Raw scan response:', data);
    const fresh = normalizeScanResult(data, url, 'backend');
    if (!fresh.success) throw Object.assign(new Error('Invalid normalized scan result'), { kind: data?.success === false ? 'analysis' : 'invalid_response' });
    const merged = mergeScanResults(currentResult, fresh);
    scanStatus = 'success'; setBackendStatus('online'); showResult(merged);
    await chrome.storage.local.set({ lastScan: merged, scanCacheSchemaVersion: CACHE_SCHEMA_VERSION });
    await loadHistory();
  } catch (error) {
    console.error('Raw scan error:', error);
    console.error('Backend error response:', error?.data);
    const classifiedError = classifyError(error, 'scan');
    console.error('Classified scan error:', classifiedError);
    showScanFailure(classifiedError);
  } finally { elements.button.disabled = false; elements.button.textContent = 'Scan'; }
}

async function loadHistory() {
  try {
    const rows = await request('/history', {}, 5000);
    if (!Array.isArray(rows) || !rows.length) { elements.history.innerHTML = '<p class="empty">No scans yet.</p>'; return; }
    elements.history.innerHTML = rows.slice(0, 5).map((row) => `<article><div><strong>${escapeHtml(row.url || 'Unknown')}</strong><span>${escapeHtml(row.status || 'UNKNOWN')}</span></div><b>${globalThis.PhishGuardResults.validScore(row.risk_score) ?? '—'}</b></article>`).join('');
  } catch { elements.history.innerHTML = '<p class="empty">History unavailable.</p>'; }
}

async function initialize() {
  if (initialized) return;
  initialized = true;
  setBackendStatus('checking');
  const healthy = await checkHealth();
  const [tab, data] = await Promise.all([activeTab(), storageGet(['lastScan', 'scanCacheSchemaVersion'])]);
  const url = normalizeUrl(tab?.url || '');
  if (url) { elements.input.value = url; elements.currentSite.textContent = url; }
  if (data.scanCacheSchemaVersion === CACHE_SCHEMA_VERSION && normalizeUrl(data.lastScan?.url) === url) {
    const source = data.lastScan.source === 'browser_warning' ? 'browser_warning' : 'cache';
    const cached = normalizeScanResult(data.lastScan, url, source);
    if (cached.success) showResult(cached, healthy ? '' : 'Latest backend check was unavailable.');
  }
  await loadHistory();
}

elements.form.addEventListener('submit', (event) => { event.preventDefault(); scan(elements.input.value.trim()); });
elements.refresh.addEventListener('click', loadHistory);
initialize();
