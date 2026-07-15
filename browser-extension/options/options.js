const { API_BASE_URL } = PhishGuardApi;

document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('backend-url');
  const status = document.getElementById('status');
  const saveBtn = document.getElementById('save-btn');

  if (!input || !status || !saveBtn) return;

  chrome.storage.local.get(['pg_backendUrl'], (data) => {
    input.value = API_BASE_URL;
  });

  saveBtn.addEventListener('click', () => {
    chrome.storage.local.set({ pg_backendUrl: API_BASE_URL }, () => {
      status.textContent = `Backend URL: ${API_BASE_URL}`;
    });
  });
});
