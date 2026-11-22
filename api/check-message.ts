declare const process: { env: Record<string, string | undefined> };
type Level = "critical" | "high" | "medium" | "low";
type Finding = { level: Level; title: string; detail: string };

function analyse(message: string) {
  const findings: Finding[] = [];
  const add = (level: Level, title: string, detail: string) => findings.push({ level, title, detail });
  if (/(otp|one.time.password|password|pin|cvv|bank details|verification code|پاس ورڈ|او ٹی پی|پن کوڈ)/i.test(message))
    add("critical", "Sensitive information request", "Never share OTPs, passwords, PINs, CVV or banking details through a message or link.");
  if (/(bit\.ly|tinyurl\.com|t\.co|rb\.gy|cutt\.ly|shorturl\.at)/i.test(message))
    add("high", "Shortened link detected", "The final destination is hidden. Verify the sender and destination independently.");
  if (/(urgent|immediately|account.{0,20}blocked|verify now|act now|limited time|فوری|اکاؤنٹ بند)/i.test(message))
    add("medium", "Urgent pressure language", "Scam messages often pressure people to act before checking the request.");
  if (/(you won|claim.{0,20}prize|free gift|انعام|لاٹری|مفت تحفہ)/i.test(message))
    add("medium", "Unexpected reward wording", "Unexpected prizes that request fees or personal information are a common fraud pattern.");
  if (/(send money|transfer|payment required|processing fee|advance fee|رقم بھیجیں|فیس جمع|ایزی پیسہ|جاز کیش)/i.test(message))
    add("high", "Payment request detected", "Verify payment requests using an official number or app you open yourself.");
  if (/(nccia|fia|police|bank|easypaisa|jazzcash|nadra|government|حکومت|بینک)/i.test(message))
    add("medium", "Organisation name mentioned", "Names and logos can be copied. Contact the organisation through its official channel.");
  const scamPatterns: Array<{ regex: RegExp; level: Level; title: string; detail: string }> = [
    { regex: /(?:free|instant|unlimited|cheap|buy|get)\s*(?:instagram\s*)?(?:followers?|likes?|views?|comments?)/i, level: "high", title: "Fake social engagement offer", detail: "Free or unusually cheap followers, likes and views are commonly used to lure users into fake login pages, surveys or payment traps." },
    { regex: /(?:free|instant|unlimited|cheap|get)\s*(?:youtube\s*)?(?:subscribers?|watch\s*time|views?)/i, level: "high", title: "Fake YouTube growth offer", detail: "Free subscriber or watch-time offers may be used to steal account credentials or collect personal information." },
    { regex: /(?:free|claim|get|generator|unlimited)\s*(?:free\s*)?(?:fire\s*)?(?:diamonds?|diamond\s*generator)|(?:free|claim|get|generator|unlimited)\s*(?:pubg\s*)?(?:uc|unknown\s*cash)/i, level: "high", title: "Free game currency bait", detail: "Free Free Fire diamonds or PUBG UC generators are a common scam lure. Never share game passwords, OTPs or payment details." },
    { regex: /(?:free|claim|get|unlimited|bonus)\s*(?:internet|mobile\s*data|data\s*pack|mbs?|gb|4g|5g)|(?:internet|data)\s*(?:free|offer|reward)/i, level: "high", title: "Free internet / MB offer", detail: "Free internet and data links may imitate mobile networks to collect phone numbers, account credentials or survey responses." },
    { regex: /(?:free|claim|get|win|exclusive)\s*(?:gift|giveaway|prize|reward|voucher|cash)/i, level: "medium", title: "Reward / giveaway bait", detail: "Unexpected prizes and rewards are often used to collect personal information or demand fake processing fees." },
    { regex: /(?:instagram|facebook|tiktok|youtube|pubg|free\s*fire).{0,45}(?:login|verify|claim|free|reward|generator)/i, level: "medium", title: "Platform or game impersonation bait", detail: "A familiar platform or game name combined with a login, verification or reward claim may be impersonation. Verify through the official app." }
  ];
  for (const pattern of scamPatterns) if (pattern.regex.test(message)) add(pattern.level, pattern.title, pattern.detail);
  if (!findings.length)
    add("low", "No obvious warning pattern", "No common scam pattern was detected. This cannot prove the message or sender is genuine.");
  const level: Level = findings.some(x => x.level === "critical") ? "critical" : findings.some(x => x.level === "high") ? "high" : findings.some(x => x.level === "medium") ? "medium" : "low";
  const verdict = level === "critical" || level === "high" ? "Warning — suspicious signs found" : level === "medium" ? "Review carefully" : "No obvious warning pattern";
  return { status: "analysed", verdict, level, findings, stored: false };
}

export default async function handler(req: any, res: any) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (req.method !== "POST") return res.status(405).json({ status: "error", message: "Use POST." });
  const message = typeof req.body?.message === "string" ? req.body.message.trim() : "";
  if (!message) return res.status(400).json({ status: "error", message: "Paste a message to analyse." });
  if (message.length > 12000) return res.status(413).json({ status: "error", message: "Message is too long. Maximum 12,000 characters." });
  return res.status(200).json(analyse(message));
}
