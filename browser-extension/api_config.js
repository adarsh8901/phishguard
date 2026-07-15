(function (root) {
  'use strict';
  root.PhishGuardApi = Object.freeze({
    API_BASE_URL: 'http://127.0.0.1:8080',
    HEALTH_TIMEOUT_MS: 3000,
    HEALTH_RETRY_DELAY_MS: 300,
    SCAN_TIMEOUT_MS: 25000,
  });
}(globalThis));
