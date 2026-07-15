(function (root) {
  'use strict';

  const CACHE_SCHEMA_VERSION = 2;
  const STATUSES = ['SAFE', 'SUSPICIOUS', 'DANGEROUS', 'UNKNOWN'];
  const PRIORITY = { UNKNOWN: 0, SAFE: 1, SUSPICIOUS: 2, DANGEROUS: 3 };

  function normalizeUrl(url) {
    try {
      const parsed = new URL(String(url || '').trim());
      if (!['http:', 'https:'].includes(parsed.protocol)) return '';
      parsed.hash = '';
      return parsed.href;
    } catch {
      return '';
    }
  }

  function validScore(value) {
    if (value === null || value === undefined || typeof value === 'boolean'
        || (typeof value === 'string' && value.trim() === '')) return null;
    const score = Number(value);
    return Number.isFinite(score) && score >= 0 && score <= 100 ? score : null;
  }

  function firstDefined(values) {
    return values.find((value) => value !== undefined);
  }

  function normalizeScanResult(raw, fallbackUrl = '', source = 'backend') {
    const data = raw && typeof raw === 'object' ? raw : {};
    const nested = data.result && typeof data.result === 'object' ? data.result : {};
    const riskScore = validScore(firstDefined([
      data.risk_score, data.score, data.risk, data.riskScore,
      nested.risk_score, nested.score,
    ]));
    let status = String(firstDefined([
      data.status, data.verdict, data.prediction, data.label,
      nested.status, nested.verdict, nested.prediction, nested.label,
    ]) || '').toUpperCase();
    if (status === 'PHISHING' || status === 'MALICIOUS' || status === 'CRITICAL' || status === 'HIGH') status = 'DANGEROUS';
    if (status === 'WARNING') status = 'SUSPICIOUS';
    if (!STATUSES.includes(status)) {
      status = riskScore === null ? 'UNKNOWN' : riskScore >= 70 ? 'DANGEROUS' : riskScore >= 40 ? 'SUSPICIOUS' : 'SAFE';
    }
    const url = normalizeUrl(data.url || nested.url || fallbackUrl);
    const reasonsValue = firstDefined([data.reasons, nested.reasons, data.blocking_reasons, data.feature_importance]);
    const reasons = Array.isArray(reasonsValue) ? reasonsValue.map((reason) =>
      typeof reason === 'string' ? reason : String(reason?.feature || reason?.reason || '')
    ).filter(Boolean) : [];
    const confidenceValue = firstDefined([data.confidence, data.confidence_percentage, nested.confidence]);
    let confidence = validScore(confidenceValue);
    if (confidence !== null && confidence <= 1 && !Number.isInteger(confidenceValue)) confidence *= 100;
    const success = data.success !== false && riskScore !== null && status !== 'UNKNOWN' && Boolean(url);
    return {
      url,
      status: success ? status : 'UNKNOWN',
      risk_score: success ? riskScore : null,
      confidence: confidence ?? 0,
      recommendation: String(data.recommendation || nested.recommendation || data.explanation || ''),
      reasons,
      source: ['backend', 'browser_warning', 'cache'].includes(source) ? source : 'backend',
      success,
      error: success ? null : String(data.error || 'INVALID_SCAN_RESULT'),
      scanned_at: String(data.scanned_at || data.created_at || new Date().toISOString()),
    };
  }

  function mergeScanResults(current, fresh) {
    if (!current?.success) return fresh;
    if (!fresh?.success) return current;
    if (current.source === 'browser_warning' && current.status === 'DANGEROUS') {
      return { ...current, supplementary_analysis: fresh };
    }
    return PRIORITY[fresh.status] >= PRIORITY[current.status] ? fresh : current;
  }

  root.PhishGuardResults = Object.freeze({
    CACHE_SCHEMA_VERSION,
    normalizeUrl,
    validScore,
    normalizeScanResult,
    mergeScanResults,
  });
}(globalThis));
