const reason = document.getElementById('reason');
const blockedUrlEl = document.getElementById('blocked-url');
const goBackButton = document.getElementById('go-back');
const continueButton = document.getElementById('continue');
const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get('blockedUrl');

chrome.storage.local.get(['lastScan'], (data) => {
  const scan = data.lastScan;
  if (scan) {
    reason.textContent = `This site is blocked because ${scan.domain} is rated ${scan.risk_classification} (${scan.risk_score}).`;
  }
  if (blockedUrl) {
    blockedUrlEl.textContent = `Blocked URL: ${blockedUrl}`;
  }
});

goBackButton.addEventListener('click', () => {
  window.history.back();
});

continueButton.addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'bypass_warning' });
  try {
    const target = new URL(blockedUrl || 'about:blank', window.location.origin);
    if (target.protocol === 'http:' || target.protocol === 'https:') {
      window.location.href = target.toString();
      return;
    }
  } catch {
    // fall through to the safe default below
  }
  window.location.href = 'about:blank';
});

