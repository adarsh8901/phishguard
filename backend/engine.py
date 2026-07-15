import re
import socket
import ssl
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from urllib.request import Request, urlopen
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

BASE_DIR = Path(__file__).resolve().parent
LOGGER = logging.getLogger("phishguard.engine")
DNS_TIMEOUT_SECONDS = 4
SSL_TIMEOUT_SECONDS = 5

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "wallet",
    "password",
    "signin",
    "confirm",
    "limited",
    "alert",
    "unlock",
    "gift",
    "billing",
    "invoice",
    "security",
    "challenge",
    "authenticate",
    "renew",
    "support",
    "refund",
    "suspend",
    "unauthorized",
]
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "buff.ly",
    "trib.al",
    "soo.gd",
    "shorte.st",
}
BAD_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "click",
    "work",
    "loan",
    "review",
    "download",
    "support",
    "online",
    "bid",
    "party",
}
SUSPICIOUS_QUERY_KEYS = {
    "login",
    "user",
    "email",
    "pass",
    "password",
    "token",
    "auth",
    "session",
    "credential",
    "redirect",
    "verification",
}
DANGEROUS_FILE_EXTENSIONS = {
    ".zip",
    ".exe",
    ".scr",
    ".msi",
    ".cab",
    ".rar",
    ".7z",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".rtf",
}
BRANDS = [
    "paypal",
    "google",
    "facebook",
    "apple",
    "microsoft",
    "amazon",
    "netflix",
    "instagram",
    "binance",
    "sbi",
    "hdfc",
    "icici",
    "allegro",
]
HOMOGLYPHS = set("аесорхуіјӏԁԛԝ")
KNOWN_ISSUERS = {
    "Let's Encrypt",
    "Let's Encrypt Authority",
    "Let's Encrypt Authority X3",
    "DigiCert",
    "DigiCert Inc",
    "DigiCert Global CA",
    "GlobalSign",
    "Sectigo",
    "GoDaddy",
    "Amazon",
    "Cloudflare, Inc.",
    "Google Trust Services",
}

TRUSTED_DOMAINS = {
    "google.com",
    "www.google.com",
    "accounts.google.com",
    "gstatic.com",
    "googleapis.com",
    "youtube.com",
    "github.com",
    "microsoft.com",
    "openai.com",
    "chatgpt.com",
}


def is_trusted_domain(hostname):
    host = (hostname or "").lower().rstrip(".")
    return any(
        host == trusted or host.endswith("." + trusted)
        for trusted in TRUSTED_DOMAINS
    )


def normalize_url(raw):
    value = (raw or "").strip()
    if not value:
        raise ValueError("URL required")
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not parsed.netloc or not hostname:
        raise ValueError("Valid URL required")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not supported")
    try:
        port = parsed.port
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except ValueError as error:
        raise ValueError("Valid URL required") from error
    except UnicodeError as error:
        raise ValueError("Valid international hostname required") from error
    normalized_host = f"[{ascii_hostname}]" if ":" in ascii_hostname else ascii_hostname
    netloc = f"{normalized_host}:{port}" if port else normalized_host
    return urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path or "", parsed.query, parsed.fragment)
    )


def domain_of(url):
    return (urlsplit(url).hostname or "").lower()


def dns_lookup(domain, use_network=True):
    if not use_network:
        return {
            "checked": False,
            "resolved": False,
            "host": None,
            "aliases": [],
            "records": {"A": [], "AAAA": []},
            "all_addresses": [],
        }
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(DNS_TIMEOUT_SECONDS)
        try:
            info = socket.getaddrinfo(domain, None)
        finally:
            socket.setdefaulttimeout(old_timeout)
        ipv4 = sorted({row[4][0] for row in info if row[0] == socket.AF_INET})
        ipv6 = sorted({row[4][0] for row in info if row[0] == socket.AF_INET6})
        host, aliases, addrs = socket.gethostbyname_ex(domain)
        return {
            "checked": True,
            "resolved": True,
            "host": host,
            "aliases": aliases,
            "records": {"A": ipv4, "AAAA": ipv6},
            "all_addresses": sorted(set(ipv4 + ipv6 + addrs)),
        }
    except Exception as error:
        LOGGER.warning("DNS lookup failed for %s: %s", domain, error)
        return {
            "checked": True,
            "resolved": False,
            "error": str(error),
            "host": None,
            "aliases": [],
            "records": {"A": [], "AAAA": []},
            "all_addresses": [],
        }


def ssl_lookup(domain, scheme, use_network=True):
    if scheme != "https" or not use_network:
        return {
            "checked": False,
            "valid": False,
            "issuer": "None",
            "days_to_expiry": None,
        }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=SSL_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
        expires = datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        issuer = {
            key: value
            for relative_distinguished_name in cert.get("issuer", ())
            for key, value in relative_distinguished_name
        }
        return {
            "checked": True,
            "valid": True,
            "issuer": issuer.get("organizationName", "Unknown"),
            "days_to_expiry": (
                expires - datetime.now(timezone.utc)
            ).days,
        }
    except Exception as error:
        LOGGER.warning("SSL lookup failed for %s: %s", domain, error)
        return {
            "checked": True,
            "valid": False,
            "issuer": "Unknown",
            "days_to_expiry": None,
            "error": str(error),
        }


def _timed_stage(name, function, *args):
    started = time.perf_counter()
    try:
        return function(*args)
    except Exception as error:
        LOGGER.warning("Optional %s analysis failed: %s", name, error)
        raise
    finally:
        LOGGER.info("%s stage took %.2fs", name, time.perf_counter() - started)


def _future_result(name, future, timeout, fallback):
    try:
        return future.result(timeout=timeout)
    except FutureTimeout:
        LOGGER.warning("Optional %s analysis timed out", name)
        return fallback
    except Exception as error:
        LOGGER.warning("Optional %s analysis failed: %s", name, error)
        return fallback


def _empty_dns(error):
    return {"checked": False, "resolved": False, "error": error, "host": None,
            "aliases": [], "records": {"A": [], "AAAA": []}, "all_addresses": []}


def _empty_ssl(error):
    return {"checked": False, "valid": False, "issuer": "Unknown",
            "days_to_expiry": None, "error": error}


def _empty_registration(error):
    return {"checked": False, "created_at": None, "domain_age_days": None,
            "registrar": None, "error": error}


def extract_features(url, use_network=True):
    stage_started = time.perf_counter()
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    domain = domain_of(normalized)
    tld = domain.split(".")[-1]
    path_parts = [part for part in parsed.path.split("/") if part]
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_keys = [
        key.lower()
        for key, _value in query_pairs
        if key.lower() in SUSPICIOUS_QUERY_KEYS
    ]
    path_keywords = [word for word in SUSPICIOUS_WORDS if word in parsed.path.lower()]
    domain_keywords = [word for word in SUSPICIOUS_WORDS if word in domain]
    keywords = sorted(set(path_keywords + domain_keywords))
    has_suspicious_extension = any(parsed.path.lower().endswith(ext) for ext in DANGEROUS_FILE_EXTENSIONS)
    brand_hits = [
        brand
        for brand in BRANDS
        if brand in domain.replace("-", "") and not domain.endswith(brand + ".com")
    ]
    LOGGER.info("URL parsing stage took %.2fs", time.perf_counter() - stage_started)
    network_started = time.perf_counter()
    if use_network:
        # Independent remote evidence is collected concurrently. Each helper has
        # its own strict socket/HTTP timeout, so one slow provider cannot serialize
        # the entire scan.
        pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="scan-stage")
        try:
            dns_future = pool.submit(_timed_stage, "DNS", dns_lookup, domain, True)
            ssl_future = pool.submit(_timed_stage, "SSL", ssl_lookup, domain, parsed.scheme, True)
            registration_future = pool.submit(_timed_stage, "WHOIS/domain-age", registration_lookup, domain, True)
            dns_result = _future_result("DNS", dns_future, DNS_TIMEOUT_SECONDS + 0.5, _empty_dns("DNS lookup timed out"))
            ssl_result = _future_result("SSL", ssl_future, SSL_TIMEOUT_SECONDS + 0.5, _empty_ssl("SSL lookup timed out"))
            registration = _future_result("WHOIS/domain-age", registration_future, 5, _empty_registration("Domain-age lookup timed out"))
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        hosting = _timed_stage("Hosting", hosting_lookup, dns_result, True)
    else:
        dns_result = dns_lookup(domain, use_network=False)
        ssl_result = ssl_lookup(domain, parsed.scheme, use_network=False)
        registration = registration_lookup(domain, use_network=False)
        hosting = hosting_lookup(dns_result, use_network=False)
    LOGGER.info("Network evidence stages took %.2fs total", time.perf_counter() - network_started)
    issuer_name = (ssl_result.get("issuer") or "").strip()
    ssl_known = issuer_name in KNOWN_ISSUERS
    short_lived = False
    try:
        days = ssl_result.get("days_to_expiry")
        short_lived = days is not None and days < 30
    except Exception:
        short_lived = False
    return {
        "scheme": parsed.scheme,
        "domain": domain,
        "path": parsed.path or "/",
        "query": parsed.query,
        "fragment": parsed.fragment,
        "path_depth": len(path_parts),
        "url_length": len(normalized),
        "domain_length": len(domain),
        "has_https": int(parsed.scheme == "https"),
        "num_special_chars": len(
            re.findall(
                r"[@&%#?=/\\_~;,!$*+\[\](){}|^-]",
                normalized,
            )
        ),
        "num_digits": len(re.findall(r"\d", normalized)),
        "num_domain_digits": len(re.findall(r"\d", domain)),
        "num_letters": len(re.findall(r"[a-zA-Z]", normalized)),
        "has_ip": int(
            bool(
                re.fullmatch(
                    r"\d{1,3}(\.\d{1,3}){3}", domain
                )
            )
        ),
        "num_subdomains": max(domain.count(".") - 1, 0),
        "has_suspicious_tld": int(tld in BAD_TLDS),
        "has_login_keywords": int(bool(keywords)),
        "suspicious_keywords": keywords,
        "suspicious_domain_keywords": domain_keywords,
        "is_url_shortener": int(domain in SHORTENERS),
        "tld": tld,
        "domain_age_days": registration.get("domain_age_days"),
        "dns": dns_result,
        "dns_checked": int(dns_result["checked"]),
        "dns_resolved": int(dns_result["resolved"]),
        "dns_records_count": len(dns_result["all_addresses"]),
        "dns_host": dns_result["host"],
        "dns_aliases": dns_result["aliases"],
        "hosting": hosting,
        "hosting_country": hosting["country"],
        "hosting_organization": hosting["organization"],
        "registration": registration,
        "ssl": ssl_result,
        "ssl_checked": int(ssl_result["checked"]),
        "ssl_known_issuer": int(ssl_known),
        "ssl_short_lived": int(short_lived),
        "blacklist_status": "not_listed",
        "brand_impersonation": brand_hits,
        "misleading_domain_structure": int(bool(brand_hits) and domain.count(".") >= 2),
        "suspicious_numeric_suffix": int(bool(re.search(r"-\d{5,}(?:\.|$)", domain))),
        "homograph_attack": int(any(char in HOMOGLYPHS for char in domain)),
        "contains_at_symbol": int("@" in normalized),
        "contains_double_slash_path": int(
            "//"
            in normalized.replace(parsed.scheme + "://", "", 1)
        ),
        "contains_dash_in_domain": int("-" in domain),
        "has_digits_in_domain": int(bool(re.search(r"\d", domain))),
        "has_fragment_keywords": 0,
        "query_param_count": len(query_pairs),
        "has_many_query_params": int(len(query_pairs) > 4),
        "contains_suspicious_query": int(bool(query_keys)),
        "query_keys": query_keys,
        "has_suspicious_path": int(bool(path_keywords)),
        "path_suspicious_keywords": path_keywords,
        "has_suspicious_fragment": 0,
        "has_dangerous_extension": int(has_suspicious_extension),
        "many_path_segments": int(len(path_parts) > 4),
        "entropy_hint": round(len(set(normalized)) / max(len(normalized), 1), 3),
    }


def calculate_risk(features):
    host_checks = [
        ("many_domain_digits", features.get("num_domain_digits", 0) > 5, 12),
        ("ip_address", features["has_ip"], 14),
        ("many_subdomains", features["num_subdomains"] > 2, 10),
        ("suspicious_tld", features["has_suspicious_tld"], 8),
        ("url_shortener", features["is_url_shortener"], 9),
        ("new_domain", features.get("domain_age_days") is not None and features["domain_age_days"] < 180, 15),
        (
            "dns_unresolved",
            features.get("dns_checked") and not features["dns_resolved"],
            20,
        ),
        ("blacklisted", features["blacklist_status"] == "blocked", 25),
        ("brand_impersonation", bool(features["brand_impersonation"]), 35),
        ("misleading_domain_structure", bool(features.get("misleading_domain_structure")), 18),
        ("suspicious_numeric_suffix", bool(features.get("suspicious_numeric_suffix")), 12),
        ("suspicious_domain_keywords", bool(features["suspicious_domain_keywords"]), 12),
        ("homograph_attack", features["homograph_attack"], 14),
    ]
    path_checks = [
        ("path_depth", features.get("path_depth", 0) > 3, 9),
        ("suspicious_path", bool(features["has_suspicious_path"]), 10),
        (
            "login_on_short_domain",
            features["has_login_keywords"]
            and features["domain_length"] < 20
            and features["num_subdomains"] <= 1,
            16,
        ),
        (
            "root_login",
            features["has_login_keywords"]
            and features.get("path_depth", 0) == 1,
            20,
        ),
        ("dangerous_extension", bool(features["has_dangerous_extension"]), 12),
        ("many_path_segments", bool(features["many_path_segments"]), 6),
    ]
    transport_checks = [
        (
            "bad_ssl",
            features.get("scheme") == "https"
            and features.get("ssl_checked")
            and not features.get("ssl", {}).get("error")
            and not features["ssl"]["valid"],
            18,
        ),
        ("short_lived_cert", features.get("ssl_short_lived", False), 10),
        (
            "unknown_issuer",
            features.get("ssl", {}).get("valid")
            and not features.get("ssl_known_issuer", 0),
            8,
        ),
        ("missing_https", not features["has_https"], 6),
    ]
    capped_url_checks = [
        ("long_url", features["url_length"] > 120, 3),
        ("many_special_chars", features["num_special_chars"] > 12, 3),
        ("many_query_params", bool(features["has_many_query_params"]), 3),
        ("query_suspicious", bool(features["contains_suspicious_query"]), 5),
        ("structure_entropy_low", features.get("entropy_hint", 1.0) < 0.18, 2),
    ]
    checks = host_checks + path_checks + transport_checks
    reasons = [
        {"feature": name, "impact": impact}
        for name, active, impact in checks
        if active
    ]
    capped_reasons = [
        {"feature": name, "impact": impact}
        for name, active, impact in capped_url_checks
        if active
    ]
    capped_total = min(sum(item["impact"] for item in capped_reasons), 10)
    if capped_total:
        reasons.append({"feature": "url_query_complexity", "impact": capped_total})
    score = min(sum(item["impact"] for item in reasons), 100)
    if score < 40:
        label = "Safe"
    elif score < 70:
        label = "Suspicious"
    elif score < 85:
        label = "High"
    else:
        label = "Critical"
    return score, label, sorted(reasons, key=lambda item: item["impact"], reverse=True)


def analyze_url(url, use_network=True):
    normalized = normalize_url(url)
    LOGGER.info("Beginning URL analysis for %s://%s%s", urlsplit(normalized).scheme, domain_of(normalized), urlsplit(normalized).path[:80])
    features = extract_features(normalized, use_network=use_network)
    warnings = [] if use_network else ["network_checks_disabled"]
    for name, result in (("dns", features.get("dns", {})), ("ssl", features.get("ssl", {})),
                         ("whois", features.get("registration", {})), ("hosting", features.get("hosting", {}))):
        if result.get("error"):
            warnings.append(f"{name}_unavailable")
    network_complete = bool(
        use_network
        and features.get("dns_checked")
        and features.get("dns_resolved")
        and (features.get("scheme") != "https" or features.get("ssl_checked"))
        and (features.get("scheme") != "https" or features.get("ssl", {}).get("valid"))
    )
    analysis_mode = "full" if network_complete and not warnings else "heuristic_only"
    if is_trusted_domain(features["domain"]):
        result = {
            "url": normalized,
            "domain": features["domain"],
            "is_phishing": False,
            "should_block": False,
            "blocking_reasons": [],
            "status": "safe",
            "confidence": 1.0 if analysis_mode == "full" else 0.6,
            "confidence_percentage": 100 if analysis_mode == "full" else 60,
            "risk_score": 0,
            "risk_classification": "Safe",
            "severity": "safe",
            "reputation_score": 100,
            "features": {"trusted_domain": True},
            "feature_importance": [],
            "explanation": "Trusted domain allowlist match.",
            "recommendation": "No action needed.",
            "source": "trusted-domain",
            "verdict": "SAFE",
            "analysis_complete": True,
            "analysis_mode": analysis_mode,
            "warnings": warnings,
            "detection_sources": ["trusted-domain", "dns", "ssl"] if network_complete else ["trusted-domain"],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }


        print(
            "[PhishGuard] URL analysis",
            {
                "original_url": url,
                "hostname": features["domain"],
                "rule_scores": [],
                "final_score": 0,
                "verdict": "Safe",
                "decision": "not redirecting: trusted domain",
            },
        )
        return result

    score, label, reasons = calculate_risk(features)
    confirmed_blacklist = features["blacklist_status"] == "blocked"
    clear_ip_phishing = bool(
        features["has_ip"]
        and (
            features["has_login_keywords"]
            or features["contains_suspicious_query"]
            or features["has_dangerous_extension"]
        )
    )
    confirmed_impersonation = bool(
        features["homograph_attack"] or features["brand_impersonation"]
    )
    blocking_reasons = []
    if score >= 70:
        blocking_reasons.append("risk score is 70 or higher")
    if confirmed_blacklist:
        blocking_reasons.append("confirmed blacklist match")
    if clear_ip_phishing:
        blocking_reasons.append("clear IP-address phishing URL")
    if confirmed_impersonation:
        blocking_reasons.append("confirmed homograph or impersonation attack")
    should_block = bool(blocking_reasons)
    phishing = should_block
    published_score = score
    published_label = label
    result = {
        "url": normalized,
        "domain": features["domain"],
        "is_phishing": phishing,
        "should_block": should_block,
        "blocking_reasons": blocking_reasons,
        "status": (
            "dangerous" if should_block
            else "warning" if score >= 40
            else "safe"
        ),
        "confidence": round(max(score, 100 - score) / 100 * (1 if analysis_mode == "full" else .65), 3),
        "confidence_percentage": round(max(score, 100 - score) * (1 if analysis_mode == "full" else .65)),
        "risk_score": published_score,
        "risk_classification": published_label,
        "severity": published_label.lower(),
        "reputation_score": 100 - score,
        "features": features,
        "feature_importance": reasons[:8],
        "explanation": (
            "Suspicious traits: "
            + ", ".join(
                r["feature"].replace("_", " ") for r in reasons[:4]
            )
            if phishing
            else "No major phishing indicators found."
        ),
        "recommendation": (
            "Do not enter credentials or payment details."
            if phishing
            else "Verify the domain before sharing sensitive data."
        ),
        "source": "python-engine",
        "verdict": (
            "DANGEROUS" if should_block
            else "SUSPICIOUS" if score >= 40
            else "SAFE"
        ),
        "analysis_complete": True,
        "analysis_mode": analysis_mode,
        "warnings": warnings,
        "detection_sources": ["url-rules"] + (["dns", "ssl"] if network_complete else []),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    print(
        "[PhishGuard] URL analysis",
        {
            "original_url": url,
            "hostname": features["domain"],
            "rule_scores": reasons,
            "final_score": score,
            "verdict": label,
            "decision": (
                "redirecting: " + ", ".join(blocking_reasons)
                if should_block
                else "not redirecting: blocking policy not met"
            ),
        },
    )
    LOGGER.info("Completed URL analysis for %s with score %s (%s)", features["domain"], score, analysis_mode)
    return result
def hosting_lookup(dns_result, use_network=True):
    """Best-effort country/organization metadata for the resolved IP."""
    ip = (dns_result.get("all_addresses") or [None])[0]
    result = {"checked": False, "ip": ip, "country": None, "organization": None}
    if not use_network or not ip:
        return result
    try:
        request = Request(f"https://ipwho.is/{ip}", headers={"User-Agent": "PhishGuard/1.0"})
        with urlopen(request, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
        result.update({"checked": True, "country": payload.get("country"), "organization": (payload.get("connection") or {}).get("org")})
    except Exception as error:
        LOGGER.warning("Hosting lookup failed for %s: %s", ip, error)
        result.update({"checked": True, "error": str(error)})
    return result


def registration_lookup(domain, use_network=True):
    """Best-effort RDAP registration age lookup."""
    result = {"checked": False, "created_at": None, "domain_age_days": None, "registrar": None}
    if not use_network:
        return result
    try:
        request = Request(f"https://rdap.org/domain/{domain}", headers={"User-Agent": "PhishGuard/1.0"})
        with urlopen(request, timeout=4) as response:
            payload = json.loads(response.read().decode("utf-8"))
        created = next((event.get("eventDate") for event in payload.get("events", []) if event.get("eventAction") in {"registration", "created"}), None)
        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00")) if created else None
        result.update({"checked": True, "created_at": created, "domain_age_days": max((datetime.now(timezone.utc) - created_dt).days, 0) if created_dt else None})
    except Exception as error:
        LOGGER.warning("WHOIS/RDAP lookup failed for %s: %s", domain, error)
        result.update({"checked": True, "error": str(error)})
    return result
