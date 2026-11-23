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
  const inspected = (u.hostname + u.pathname + " " + u.searchParams.toString()).toLowerCase().replace(/[._+%-]+/g, " ");
  const findings: Finding[] = [];
  const add = (level: Finding["level"], title: string, detail: string) => findings.push({ level, title, detail });
  const patterns: Array<{ regex: RegExp; title: string; detail: string; level: Finding["level"] }> = [
    { regex: /(?:free|instant|unlimited|cheap|buy|get)\s*(?:instagram\s*)?(?:followers?|likes?|views?|comments?)/i, title: "Fake social engagement offer", detail: "Free or unusually cheap followers, likes or views are commonly used to collect logins, payment details or survey data.", level: "high" },
    { regex: /(?:free|instant|unlimited|cheap|get|claim)\s*(?:youtube\s*)?(?:subscribers?|watch\s*time|views?)/i, title: "Fake YouTube growth offer", detail: "Free subscriber or watch-time offers can be used for credential theft, fake engagement or misleading surveys.", level: "high" },
    { regex: /(?:free|claim|get|generator|unlimited)\s*(?:free\s*)?(?:fire\s*)?(?:diamonds?|diamond\s*generator)|(?:free|claim|get|generator|unlimited)\s*(?:pubg\s*)?(?:uc|unknown\s*cash)/i, title: "Free game currency offer", detail: "Free diamonds or UC generator pages are a common bait pattern. Never provide game credentials, OTPs or payment details.", level: "high" },
    { regex: /(?:free|claim|get|unlimited|bonus)\s*(?:internet|mobile\s*data|data\s*pack|mbs?|gb|4g|5g)|(?:internet|data)\s*(?:free|offer|reward)/i, title: "Free internet / data bait", detail: "Unexpected free internet or data claims may lead to fake carrier login pages, surveys or personal-data collection.", level: "high" },
    { regex: /(?:free|claim|get|win|exclusive)\s*(?:gift|giveaway|prize|reward|voucher|cash)/i, title: "Reward / giveaway bait", detail: "Unexpected reward links are often used to collect personal information or demand a processing fee.", level: "medium" },
    { regex: /(?:instagram|facebook|tiktok|youtube|pubg|free\s*fire).{0,35}(?:login|verify|claim|free|reward|generator)/i, title: "Brand-themed login or reward bait", detail: "A familiar platform or game name combined with a login, verification or reward claim may be impersonation. Check the exact registered domain.", level: "medium" }
    { regex: /(?:login|signin|verify|secure|account|wallet).{0,35}(?:update|confirm|unlock|recover|validate)|(?:update|confirm|unlock|recover).{0,35}(?:login|account|wallet)/i, title: "Credential-harvesting page pattern", detail: "The URL contains account-verification or recovery language often used by fake sign-in pages. Never enter credentials unless the exact domain is confirmed through the official app.", level: "high" },
    { regex: /(?:\.apk(?:$|[?#])|download.{0,25}(?:app|apk)|install.{0,25}(?:app|profile|certificate))/i, title: "App / APK download lure", detail: "Unverified APKs or app packages can request powerful permissions or contain unwanted software. Do not install files from an unsolicited link.", level: "high" },
    { regex: /(?:anydesk|teamviewer| ultraviewer|rustdesk|quick.?support|remote.?access|screen.?share)/i, title: "Remote-access or screen-sharing reference", detail: "Remote-support tools can be abused to watch your screen or control a device. Never install or share a session code because an unsolicited sender asks you to.", level: "high" },
    { regex: /(?:seed.?phrase|recovery.?phrase|private.?key|wallet.?connect|airdrop|crypto.?claim|token.?claim)/i, title: "Crypto wallet / recovery phrase lure", detail: "A site asking for a wallet recovery phrase, private key or unsolicited token claim can lead to irreversible asset theft. Never disclose recovery secrets.", level: "critical" },
    { regex: /(?:job|work|salary|earning|task).{0,35}(?:registration|deposit|fee|investment)|(?:registration|deposit|fee).{0,35}(?:job|work|salary|earning|task)/i, title: "Advance-fee job or task offer", detail: "A job or task offer that requires an upfront deposit, activation fee or investment is a common advance-fee fraud pattern.", level: "high" },
    { regex: /(?:qr|scan.?code).{0,30}(?:payment|login|verify|claim)|(?:payment|login|verify|claim).{0,30}(?:qr|scan.?code)/i, title: "QR-code action bait", detail: "A QR code can hide the destination. Preview and verify the destination before opening it; never approve a payment or login prompt you did not initiate.", level: "medium" },
  ];
  for (const pattern of patterns) if (pattern.regex.test(inspected)) add(pattern.level, pattern.title, pattern.detail);
  if (u.username || u.password) add("high", "Hidden URL credentials", "This address contains user-info before the hostname. Do not sign in through it.");
  if (host.startsWith("xn--") || host.split(".").some(part => part.startsWith("xn--")))
    add("high", "Internationalized / look-alike domain", "Punycode can be used to make a domain look similar to a trusted brand. Verify the exact spelling.");
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host))
    add("high", "IP-address destination", "The link uses a raw IP address instead of a recognizable domain. Verify the destination independently.");
  if (/(bit\.ly|tinyurl\.com|t\.co|rb\.gy|cutt\.ly|shorturl\.at|is\.gd|rebrand\.ly)$/i.test(host))
    add("medium", "Shortened link detected", "The final destination is hidden until the short link is resolved. Do not open it unless you trust the sender.");
  if (u.protocol === "http:") add("medium", "Unencrypted HTTP connection", "This address does not use HTTPS. Information sent to it may not be encrypted.");
  if (/\.(zip|mov|click|top|work|country|gq|tk|ml|cf)$/i.test(host))
    add("medium", "Higher-risk domain ending", "This domain ending is sometimes abused. The ending alone does not prove a scam; verify the domain and sender.");
  if (host.split(".").length >= 5) add("medium", "Unusually deep subdomain", "Many nested subdomains can make the real registered domain harder to notice.");
  if (value.length > 180) add("low", "Unusually long URL", "Long tracking or redirect parameters can hide the final destination. Review the domain carefully.");
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


type DomainRegistration = { domain: string; registeredAt?: string; ageDays?: number; registrar?: string; status: "found" | "not_found" | "unavailable" };
function registrableDomain(host: string) {
  const clean = host.toLowerCase().replace(/^www\./, "");
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(clean) || clean.includes(":")) return "";
  const parts = clean.split(".").filter(Boolean);
  if (parts.length < 2) return "";
  const twoLevelSuffixes = new Set(["co.uk","org.uk","com.au","net.au","co.nz","com.pk","com.br","co.in","co.za"]);
  const suffix = parts.slice(-2).join(".");
  return twoLevelSuffixes.has(suffix) && parts.length >= 3 ? parts.slice(-3).join(".") : suffix;
}
async function checkDomainRegistration(host: string): Promise<DomainRegistration> {
  const domain = registrableDomain(host);
  if (!domain) return { domain: host, status: "unavailable" };
  try {
    const response = await fetch("https://rdap.org/domain/" + encodeURIComponent(domain), {
      headers: { Accept: "application/rdap+json", "User-Agent": "ZXH-Official-CyberGuard/1.0" },
      redirect: "follow",
      signal: AbortSignal.timeout(7000)
    });
    if (response.status === 404) return { domain, status: "not_found" };
    if (!response.ok) return { domain, status: "unavailable" };
    const data: any = await response.json();
    const event = Array.isArray(data.events) ? data.events.find((item: any) => item.eventAction === "registration") : undefined;
    const registeredAt = typeof event?.eventDate === "string" ? event.eventDate : undefined;
    const ageDays = registeredAt ? Math.max(0, Math.floor((Date.now() - new Date(registeredAt).getTime()) / 86400000)) : undefined;
    const registrarEntity = Array.isArray(data.entities) ? data.entities.find((item: any) => Array.isArray(item.roles) && item.roles.includes("registrar")) : undefined;
    const registrarValue = registrarEntity?.vcardArray?.[1]?.find((item: any) => item[0] === "fn")?.[3];
    return { domain, registeredAt, ageDays: Number.isFinite(ageDays) ? ageDays : undefined, registrar: typeof registrarValue === "string" ? registrarValue : undefined, status: "found" };
  } catch { return { domain, status: "unavailable" }; }
}

export default async function handler(req: any, res: any) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (req.method !== "POST") return res.status(405).json({ status: "error", message: "Use POST." });
  const url = typeof req.body?.url === "string" ? req.body.url.trim() : "";
  // Detect dotted numeric hosts before URL parsing, including malformed IPv4-like links.
  const numericHost = url.match(/(?:https?:\/\/|https?:\/+|\/\/)?(\d{1,5}(?:\.\d{1,5}){3})(?=[:/?#\s]|$)/i)?.[1];
  if (numericHost) {
    const octets = numericHost.split(".").map(Number);
    if (octets.some(part => part > 255)) {
      const finding: Finding = { level: "high", title: "Malformed numeric IP-like link", detail: "This address contains dotted numeric host segments outside the valid IPv4 range (0–255). It is malformed or deceptive and should not be opened. Verify the sender and obtain the destination from an official source." };
      return res.status(200).json({ status: "suspicious", verdict: "Malformed numeric IP link detected", level: "high", findings: [finding], sources: [], checkedSources: 0, checkedSourceNames: [], unavailableSources: ["Threat feeds skipped for malformed numeric host"], domainRegistration: { domain: numericHost, status: "unavailable" } });
    }
  }
  if (!url || url.length > 2048 || !isPublicHttpUrl(url)) {
    return res.status(400).json({ status: "error", message: "Enter a valid public HTTP or HTTPS URL." });
  }

  const normalized = normalizeUrl(url);
  const findings = localUrlFindings(url);
  const parsedTarget = new URL(url);
  const domainRegistration = await checkDomainRegistration(parsedTarget.hostname);
  if (domainRegistration.status === "found" && typeof domainRegistration.ageDays === "number" && domainRegistration.ageDays < 180) {
    findings.push({ level: "medium", title: "Recently registered domain", detail: domainRegistration.domain + " was registered " + domainRegistration.ageDays + " days ago. New domains are not automatically malicious, but deserve extra verification." });
  }
  if (parsedTarget.protocol === "https:") {
    findings.push({ level: "low", title: "HTTPS URL", detail: "The submitted address uses HTTPS. This indicates encrypted transport is requested; it does not establish that the site or its content is trustworthy." });
  }
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
    return res.status(200).json({ status: "malicious", verdict: "Known malicious URL detected", level: "critical", findings, sources: matchedSources, checkedSources, checkedSourceNames, unavailableSources, domainRegistration });
  }

  if (findings.some(f => f.level === "high" || f.level === "medium")) {
    return res.status(200).json({ status: "suspicious", verdict: "Suspicious URL characteristics found", level: findings.some(f => f.level === "high") ? "high" : "medium", findings, sources: [], checkedSources, checkedSourceNames, unavailableSources, domainRegistration });
  }

  if (checkedSources > 0) {
    findings.unshift({ level: "low", title: "No known threat-feed match", detail: "No match was found in the sources that responded (" + checkedSourceNames.join(", ") + "). " + (unavailableSources.length ? "Unavailable: " + unavailableSources.join(", ") + ". " : "") + "This is not a clean bill of health and does not prove the destination is safe." });
    return res.status(200).json({ status: "not_listed", verdict: "No known threat match — not verified safe", level: "medium", findings, sources: [], checkedSources, checkedSourceNames, unavailableSources, domainRegistration });
  }

  findings.unshift({ level: "medium", title: "Threat-intelligence lookup unavailable", detail: "No external threat feed could be confirmed during this scan. Treat this URL as unverified and do not enter sensitive information." });
  return res.status(200).json({ status: "unknown", verdict: "Reputation check incomplete", level: "medium", findings, sources: [], checkedSources: 0, checkedSourceNames, unavailableSources, domainRegistration });
}
