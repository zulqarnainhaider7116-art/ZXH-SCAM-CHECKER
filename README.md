# ZXH OFFICIAL ScamCheck

**CyberGuard Phishing Attack Shield** — a mobile-first scam-awareness and URL reputation checker.

**Created by ZULQARNAIN X HAIDER**  
**Powered by ZXH OFFICIAL**

## Features
- Welcome, dashboard, scanner, history and settings screens.
- Preserves the dark navy / emerald / cyan CyberGuard visual identity.
- Backend message pattern analysis through POST /api/check-message (message content is processed in memory and not saved).
- Live URL reputation lookup through the OpenPhish community feed.
- Optional URLhaus lookup when `URLHAUS_AUTH_KEY` is configured.
- Vercel serverless endpoints at POST /api/check-url and POST /api/check-message.

## Tech stack
React, TypeScript, Vite, Lucide React and Vercel Functions.

## Local development
```bash
npm install
npm run dev
```

Use `vercel dev` to run the serverless API route locally.

## Vercel setup
Connect this repository to Vercel with the Vite framework preset. No environment variable is required for the OpenPhish feed.
To enable the optional URLhaus source, add `URLHAUS_AUTH_KEY` under Project Settings → Environment Variables for Preview and Production.

## Important limitations
A match in a threat feed is a strong warning. A URL that is not listed is **not guaranteed safe**: feeds may be incomplete or delayed, and this tool is not a full antivirus, browser isolation service, or official NCCIA verification system. Do not enter passwords, OTPs, payment details or other secrets into suspicious pages.
