declare const process: { env: Record<string, string | undefined> };

const OPENPHISH_FEED = "https://openphish.com/feed.txt";
const URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/";
const GOOGLE_SAFE_BROWSING = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

type Finding = { level: "critical" | "high" | "medium" | "low"; title: string; detail: string };

function isPublicHttpUrl(value: string) {
  try {
    const parsed = new URL(value);
    if (!["http:", "https:"].includes(parsed.protocol)) return false;
    const host = parsed.hostname.toLowerCase();
    if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return false;
    if (/^(127\.|10\.|192\.168\.|169\.254\.)/.test(host)) return false;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return false;
    if (host === "0.0.0.0" || host === "::1" || host.startsWith("fc") || host.startsWith("fd")) return false;
    return true;
  } catch { return false; }
}

function normalizeUrl(value: string) {
  const u = new URL(value);
  u.hash = "";
  u.hostname = u.hostname.toLowerCase();
  if (u.pathname.length > 1) u.pathname = u.pathname.replace(/\/$/, "");
  return u.toString().replace(/\/$/, "").toLowerCase();
}

function localUrlFindings(value: string): Finding[] {
  const u = new URL(value);
  const host = u.hostname.toLowerCase();
  const findings: Finding[] = [];
  const add = (level: Finding["level"], title: string, detail: string) => findings.push({ level, title, detail });
  if (u.username || u.password) add("high", "Hidden URL credentials", "This address contains user-info before the hostname. Do not sign in through it.");
  if (host.startsWith("xn--") || host.split(".").some(part => part.startsWith("xn--")))
    add("high", "Internationalized / look-alike domain", "Punycode can be used to make a domain look similar to a trusted brand. Verify the exact spelling.");
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host))
    add("high", "IP-address destination", "The link uses a raw IP address instead of a recognizable domain. Verify the destination independently.");
  if (/(bit\.ly|tinyurl\.com|t\.co|rb\.gy|cutt\.ly|shorturl\.at|is\.gd|rebrand\.ly)$/i.test(host))
    add("medium", "Shortened link detected", "The final destination is hidden until the short link is resolved. Do not open it unless you trust the sender.");
  if (u.protocol === "http:")
    add("medium", "Unencrypted HTTP connection", "This address does not use HTTPS. Information sent to it may not be encrypted.");
  if (/\.(zip|mov|click|top|work|country|gq|tk|ml|cf)$/i.test(host))
    add("medium", "Higher-risk domain ending", "This domain ending is sometimes abused. The ending alone does not prove a scam; verify the domain and sender.");
  if (host.split(".").length >= 5)
    add("medium", "Unusually deep subdomain", "Many nested subdomains can make the real registered domain harder to notice.");
  if (value.length > 180)
    add("low", "Unusually long URL", "Long tracking or redirect parameters can hide the final destination. Review the domain carefully.");
  return findings;
}

async function checkGoogleSafeBrowsing(url: string, key: string) {
  const response = await fetch(GOOGLE_SAFE_BROWSING + "?key=" + encodeURIComponent(key), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client: { clientId: "zxh-official-cyberguard", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    }),
    signal: AbortSignal.timeout(9000)
  });
  if (!response.ok) throw new Error("Google Safe Browsing request failed");
  const data: any = await response.json();
  return Array.isArray(data.matches) && data.matches.length > 0;
}

export default async function handler(req: any, res: any) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (req.method !== "POST") return res.status(405).json({ status: "error", message: "Use POST." });
  const url = typeof req.body?.url === "string" ? req.body.url.trim() : "";
  if (!url || url.length > 2048 || !isPublicHttpUrl(url)) {
    return res.status(400).json({ status: "error", message: "Enter a valid public HTTP or HTTPS URL." });
  }

  const normalized = normalizeUrl(url);
  const findings = localUrlFindings(url);
  let checkedSources = 0;
  const matchedSources: string[] = [];
  const checkedSourceNames: string[] = [];
  const unavailableSources: string[] = [];

  try {
    const response = await fetch(OPENPHISH_FEED, {
      headers: { "User-Agent": "ZXH-Official-CyberGuard/1.0" },
      signal: AbortSignal.timeout(9000)
    });
    if (response.ok) {
      checkedSources++;
      checkedSourceNames.push("OpenPhish Community Feed");
      const entries = (await response.text()).split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
      if (entries.some(entry => {
        try { return normalizeUrl(entry) === normalized; } catch { return false; }
      })) matchedSources.push("OpenPhish Community Feed");
    } else {
      unavailableSources.push("OpenPhish Community Feed");
    }
  } catch { unavailableSources.push("OpenPhish Community Feed"); }

  const urlhausKey = process.env.URLHAUS_AUTH_KEY;
  if (urlhausKey) {
    try {
      const response = await fetch(URLHAUS_API, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "Auth-Key": urlhausKey, "User-Agent": "ZXH-Official-CyberGuard/1.0" },
        body: new URLSearchParams({ url }),
        signal: AbortSignal.timeout(9000)
      });
      if (response.ok) {
        const data: any = await response.json();
        if (data.query_status === "ok") matchedSources.push("URLhaus");
        if (data.query_status === "ok" || data.query_status === "no_results") {
          checkedSources++;
          checkedSourceNames.push("URLhaus");
        } else {
          unavailableSources.push("URLhaus");
        }
      } else {
        unavailableSources.push("URLhaus");
      }
    } catch { unavailableSources.push("URLhaus"); }
  } else {
    unavailableSources.push("URLhaus (optional API key not configured)");
  }

  const googleKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (googleKey) {
    try {
      if (await checkGoogleSafeBrowsing(url, googleKey)) matchedSources.push("Google Safe Browsing");
      checkedSources++;
      checkedSourceNames.push("Google Safe Browsing");
    } catch { unavailableSources.push("Google Safe Browsing"); }
  } else {
    unavailableSources.push("Google Safe Browsing (API key not configured)");
  }

  if (unavailableSources.length) {
    findings.push({ level: "low", title: "Threat-feed coverage notice", detail: "Not checked or unavailable: " + unavailableSources.join(", ") + ". Results are based only on the sources that responded and local URL indicators." });
  }

  if (matchedSources.length) {
    findings.unshift({ level: "critical", title: "Known threat intelligence match", detail: "This exact URL matched: " + matchedSources.join(", ") + ". Do not open it or enter information." });
    return res.status(200).json({ status: "malicious", verdict: "Known malicious URL detected", level: "critical", findings, sources: matchedSources, checkedSources, checkedSourceNames, unavailableSources });
  }

  if (findings.some(f => f.level === "high" || f.level === "medium")) {
    return res.status(200).json({ status: "suspicious", verdict: "Suspicious URL characteristics found", level: findings.some(f => f.level === "high") ? "high" : "medium", findings, sources: [], checkedSources, checkedSourceNames, unavailableSources });
  }

  if (checkedSources > 0) {
    findings.unshift({ level: "low", title: "No known threat-feed match", detail: "No match was found in the sources that responded (" + checkedSourceNames.join(", ") + "). " + (unavailableSources.length ? "Unavailable: " + unavailableSources.join(", ") + ". " : "") + "This is not a clean bill of health and does not prove the destination is safe." });
    return res.status(200).json({ status: "not_listed", verdict: "No known threat match — not verified safe", level: "medium", findings, sources: [], checkedSources, checkedSourceNames, unavailableSources });
  }

  findings.unshift({ level: "medium", title: "Threat-intelligence lookup unavailable", detail: "No external threat feed could be confirmed during this scan. Treat this URL as unverified and do not enter sensitive information." });
  return res.status(200).json({ status: "unknown", verdict: "Reputation check incomplete", level: "medium", findings, sources: [], checkedSources: 0, checkedSourceNames, unavailableSources });
}
