const OPENPHISH_FEED = "https://openphish.com/feed.txt";
const URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/";

function isPublicHttpUrl(value: string) {
  try {
    const parsed = new URL(value);
    if (!["http:", "https:"].includes(parsed.protocol)) return false;
    const host = parsed.hostname.toLowerCase();
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return false;
    if (/^(127\.|10\.|192\.168\.|169\.254\.)/.test(host)) return false;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return false;
    return true;
  } catch { return false; }
}

export default async function handler(req: any, res: any) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ status: "error", message: "Use POST." });
  const url = typeof req.body?.url === "string" ? req.body.url.trim() : "";
  if (!url || url.length > 2048 || !isPublicHttpUrl(url)) {
    return res.status(400).json({ status: "error", message: "Enter a valid public HTTP or HTTPS URL." });
  }

  let feedChecked = false;
  try {
    const response = await fetch(OPENPHISH_FEED, {
      headers: { "User-Agent": "ZXH-ScamCheck/1.0" },
      signal: AbortSignal.timeout(9000)
    });
    if (response.ok) {
      feedChecked = true;
      const entries = (await response.text()).split(/\r?\n/).map((x) => x.trim().toLowerCase()).filter(Boolean);
      const normalized = url.toLowerCase().replace(/\/$/, "");
      if (entries.some((x) => x.replace(/\/$/, "") === normalized)) {
        return res.status(200).json({ status: "malicious", source: "OpenPhish Community Feed" });
      }
    }
  } catch { /* optional source */ }

  const authKey = process.env.URLHAUS_AUTH_KEY;
  if (authKey) {
    try {
      const response = await fetch(URLHAUS_API, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "Auth-Key": authKey, "User-Agent": "ZXH-ScamCheck/1.0" },
        body: new URLSearchParams({ url }),
        signal: AbortSignal.timeout(9000)
      });
      if (response.ok) {
        const data: any = await response.json();
        if (data.query_status === "ok") return res.status(200).json({ status: "malicious", source: "URLhaus" });
        if (data.query_status === "no_results") feedChecked = true;
      }
    } catch { /* do not infer safety from source failure */ }
  }

  if (feedChecked) return res.status(200).json({ status: "not_listed", source: "OpenPhish" });
  return res.status(200).json({ status: "unknown", message: "Threat-intelligence feeds are currently unavailable. Only local pattern checks were applied." });
}
