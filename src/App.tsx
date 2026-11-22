import { useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowLeft, ArrowRight, Bell, ChevronRight, CircleAlert, Clock3,
  Globe2, History, Home, Link2, LockKeyhole, MessageSquareText, ScanLine,
  Settings, Shield, ShieldAlert, ShieldCheck, Sparkles, TrendingUp, X
} from 'lucide-react';

type Screen = 'welcome' | 'home' | 'scan' | 'history' | 'settings';
type Finding = { level: 'critical' | 'high' | 'medium' | 'low'; title: string; detail: string };
type PageAnalysis = { status: string; finalUrl?: string; title?: string; description?: string; keywords?: string[]; visibleTextPreview?: string; links?: string[]; forms?: string[]; iframeCount?: number; findings?: Finding[]; contentLength?: number };
type Result = { verdict: string; level: Finding['level']; findings: Finding[]; value: string; contentType?: 'url' | 'message' | 'message_with_link'; checkedSources?: string[]; unavailableSources?: string[]; pageAnalysis?: PageAnalysis; domainRegistration?: { domain: string; registeredAt?: string; ageDays?: number; registrar?: string; status: 'found' | 'not_found' | 'unavailable' } };

function inspect(value: string): Result {
  const text = value.trim();
  const lower = text.toLowerCase();
  const findings: Finding[] = [];
  const add = (level: Finding['level'], title: string, detail: string) => findings.push({ level, title, detail });
  if (/(otp|password|pin|cvv|bank details|verification code|پاس ورڈ|او ٹی پی)/i.test(text))
    add('critical', 'Sensitive information request', 'Never share OTPs, passwords, PINs, CVV or banking details through a message or link.');
  if (/(bit\.ly|tinyurl\.com|t\.co|rb\.gy|cutt\.ly)/i.test(text))
    add('high', 'Shortened link detected', 'The final destination is hidden. Verify the sender and destination independently.');
  if (/(urgent|immediately|account.*blocked|verify now|act now|فوری)/i.test(text))
    add('medium', 'Urgent pressure language', 'Scam messages often pressure people to act before checking the request.');
  if (/(you won|claim.*prize|free gift|انعام|لاٹری)/i.test(text))
    add('medium', 'Unexpected reward wording', 'Unexpected prizes that request fees or personal information are a common fraud pattern.');
  if (/(send money|transfer|payment required|processing fee|advance fee|رقم بھیجیں|فیس جمع)/i.test(text))
    add('high', 'Payment request detected', 'Verify payment requests using an official number or app you open yourself.');
  if (/(nccia|fia|police|bank|easypaisa|jazzcash|nadra|government)/i.test(text))
    add('medium', 'Organisation name mentioned', 'Names and logos can be copied. Contact the organisation through its official channel.');
  if (!findings.length) add('low', 'No obvious warning pattern', 'This quick local review cannot prove a link is safe. Verify the sender and destination before acting.');
  const level = findings.some(f => f.level === 'critical') ? 'critical' : findings.some(f => f.level === 'high') ? 'high' : findings.some(f => f.level === 'medium') ? 'medium' : 'low';
  return { verdict: level === 'critical' || level === 'high' ? 'Warning — suspicious signs found' : level === 'medium' ? 'Review carefully' : 'No obvious warning found', level, findings, value };
}

function detectContentType(value: string): 'url' | 'message' | 'message_with_link' {
  const text = value.trim();
  const urlPattern = /(https?:[/]{2}|www[.])[^ ]+|[a-z0-9-]+[.][a-z0-9-]+(?:[.][a-z0-9-]+)*(?:[/][^ ]*)?/i;
  const match = text.match(urlPattern)?.[0] || '';
  if (!match) return 'message';
  const remainder = text.replace(match, '').replace(/[ .,!?;:()[\]{}<>"']/g, '');
  return remainder === '' ? 'url' : 'message_with_link';
}

function Wave({ className = '' }: { className?: string }) {
  return <svg className={'wave ' + className} viewBox="0 0 700 230" preserveAspectRatio="none" aria-hidden="true">
    <defs><linearGradient id="waveGreen" x1="0" x2="1"><stop stopColor="#00f5a0" stopOpacity="0"/><stop offset=".48" stopColor="#00e6ad"/><stop offset="1" stopColor="#00aaff" stopOpacity=".1"/></linearGradient><linearGradient id="waveBlue" x1="0" x2="1"><stop stopColor="#007dff" stopOpacity="0"/><stop offset=".5" stopColor="#00caff"/><stop offset="1" stopColor="#36e8ff" stopOpacity="0"/></linearGradient></defs>
    <path d="M-20 130 C120 20 180 220 330 100 S520 30 730 130" stroke="url(#waveGreen)" strokeWidth="2" fill="none"/><path d="M-20 160 C140 45 190 240 350 125 S550 55 730 150" stroke="url(#waveBlue)" strokeWidth="3" fill="none"/><path d="M-20 180 C120 75 240 250 390 145 S580 90 730 180" stroke="#00baff" strokeOpacity=".35" strokeDasharray="3 7" fill="none"/>
  </svg>;
}


function RadarScanner() {
  const [paused, setPaused] = useState(false);
  const [boosted, setBoosted] = useState(false);
  const [cycle, setCycle] = useState(0);
  const targets = [{x:24,y:34},{x:68,y:24},{x:76,y:62},{x:39,y:73},{x:54,y:48},{x:18,y:67}];
  return <div className="radar-panel glass-panel page-in">
    <div className="radar-topline"><span><i className="radar-live-dot"/> ZXH RED RADAR SCANNER</span><b>SIGNAL POINTS: {targets.length.toString().padStart(2,'0')}</b></div>
    <div className={'radar-scope' + (paused ? ' paused' : '') + (boosted ? ' boosted' : '')} key={cycle}>
      <div className="radar-grid-cross"/><div className="radar-sweep"/><div className="radar-center"><Shield size={20}/></div>
      {targets.map((point,i)=><span className={'radar-blip blip-'+i} key={i} style={{left:point.x+'%',top:point.y+'%'}}/>)}
      <span className="radar-axis axis-top">N</span><span className="radar-axis axis-right">E</span><span className="radar-axis axis-bottom">S</span><span className="radar-axis axis-left">W</span>
    </div>
    <div className="radar-readout"><span><i/> SCANNING IN PROGRESS</span><b>{boosted ? 'HIGH SPEED' : 'STANDARD SPEED'}</b></div>
    <div className="radar-controls"><button onClick={()=>setPaused(v=>!v)}>{paused ? '▶ RESUME' : 'Ⅱ PAUSE'}</button><button onClick={()=>{setPaused(false);setCycle(v=>v+1);}}>↻ RESET</button><button className={boosted ? 'boost-active' : ''} onClick={()=>setBoosted(v=>!v)}>ϟ {boosted ? 'NORMAL' : 'BOOST'}</button></div>
    <p className="radar-caption">VISUAL SCAN SEQUENCE • THREAT INTELLIGENCE CHECK RUNNING</p>
  </div>;
}

function App() {
  const [screen, setScreen] = useState<Screen>('welcome');
  const radarRef = useRef<HTMLDivElement | null>(null);
  const navigateTo = (next: Screen) => {
    if (next !== screen) window.history.pushState({ zxhScreen: next }, '', '#' + next);
    setScreen(next);
  };
  useEffect(() => {
    const handleBack = () => {
      const next = (window.location.hash.replace('#', '') || 'welcome') as Screen;
      setScreen(['welcome', 'home', 'scan', 'history', 'settings'].includes(next) ? next : 'home');
    };
    window.addEventListener('popstate', handleBack);
    return () => window.removeEventListener('popstate', handleBack);
  }, []);
  const [input, setInput] = useState('');
  const [inputKind, setInputKind] = useState<'url' | 'message' | 'message_with_link'>('message');
  const autoScanTimer = useRef<number | null>(null);
  const autoScanStartedFor = useRef('');
  const [homeUrl, setHomeUrl] = useState('');
  const [result, setResult] = useState<Result | null>(null);
  const [alertDismissed, setAlertDismissed] = useState(false);

  const [history, setHistory] = useState<Result[]>(() => { try { const saved = localStorage.getItem('zxh-cyberguard-history-v1'); return saved ? (JSON.parse(saved) as Result[]).slice(0, 30) : []; } catch { return []; } });
  const [notice, setNotice] = useState('');
  useEffect(() => { try { localStorage.setItem('zxh-cyberguard-history-v1', JSON.stringify(history.slice(0, 30))); } catch { /* storage may be unavailable */ } }, [history]);
  const [scanning, setScanning] = useState(false);
  useEffect(() => {
    if (!scanning || screen !== 'scan') return;
    const timer = window.setTimeout(() => radarRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 100);
    return () => window.clearTimeout(timer);
  }, [scanning, screen]);
  const runScan = async (value = input) => {
    const submitted = value.trim();
    if (!submitted) { setNotice('Paste a message or URL first.'); return; }
    if (autoScanTimer.current !== null) { window.clearTimeout(autoScanTimer.current); autoScanTimer.current = null; }
    autoScanStartedFor.current = submitted;
    setScanning(true); setResult(null); setNotice('');
    const detectedKind = detectContentType(submitted);
    const isUrl = detectedKind === 'url';
    const scanTarget = isUrl && !/^https?:\/\//i.test(submitted) ? 'https://' + submitted : submitted;
    const minimumScanTime = new Promise(resolve => window.setTimeout(resolve, 1800));
    try {
      const response = await fetch(isUrl ? '/api/check-url' : '/api/check-message', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(isUrl ? { url: scanTarget } : { message: submitted }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || (isUrl ? 'URL check failed.' : 'Message scan failed.'));
      let next: Result;
      if (isUrl) {
        const findings: Finding[] = Array.isArray(data.findings) ? [...data.findings] : [];
        let pageAnalysis: PageAnalysis | undefined;
        try {
          const pageResponse = await fetch('/api/inspect-page', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: scanTarget }) });
          const pageData = await pageResponse.json();
          if (pageData.pageAnalysis) {
            pageAnalysis = pageData.pageAnalysis as PageAnalysis;
            if (Array.isArray(pageAnalysis.findings)) findings.push(...pageAnalysis.findings);
          }
        } catch { findings.push({ level: 'low', title: 'Page content inspection unavailable', detail: 'Threat reputation checks completed separately, but page HTML could not be inspected.' }); }
        const statusLevel: Finding['level'] = data.status === 'malicious' ? 'critical' : findings.some(f => f.level === 'critical') ? 'critical' : findings.some(f => f.level === 'high') ? 'high' : findings.some(f => f.level === 'medium') ? 'medium' : 'low';
        const verdict = data.status === 'malicious' ? 'Known malicious URL detected' : statusLevel === 'critical' ? 'Critical content indicators detected' : statusLevel === 'high' ? 'High-risk website content detected' : statusLevel === 'medium' ? 'Suspicious website indicators found' : data.status === 'not_listed' ? 'No known threat match — not verified safe' : 'Website review completed — not verified safe';
        if (!findings.length) findings.push({ level: 'low', title: 'URL review completed', detail: 'No obvious indicator was found in the checks that completed. This does not prove the destination is safe.' });
        next = { value: scanTarget, contentType: 'url', level: statusLevel, verdict, findings, pageAnalysis, checkedSources: Array.isArray(data.checkedSourceNames) ? data.checkedSourceNames : [], unavailableSources: Array.isArray(data.unavailableSources) ? data.unavailableSources : [], domainRegistration: data.domainRegistration };
      } else { next = { verdict: data.verdict, level: data.level, findings: data.findings, value: submitted, contentType: detectedKind }; }
      await minimumScanTime;
      setResult(next); setAlertDismissed(false); setHistory(old => [next, ...old].slice(0, 30)); setNotice('');
    } catch (error) {
      await minimumScanTime;
      setNotice(error instanceof Error ? error.message : 'Could not reach scanner.');
    } finally { setScanning(false); }
  };
  useEffect(() => {
    const value = input.trim();
    if (screen !== 'scan' || value.length < 8 || scanning || result?.value === value || autoScanStartedFor.current === value) return;
    const timer = window.setTimeout(() => {
      if (autoScanStartedFor.current !== value) {
        autoScanStartedFor.current = value;
        void runScan(value);
      }
    }, 1200);
    return () => window.clearTimeout(timer);
  }, [input, screen, scanning, result]);
  const runHomeUrlScan = () => {
    if (!homeUrl.trim()) { setNotice('Paste a URL first.'); return; }
    setInput(homeUrl.trim()); setResult(null); navigateTo('scan'); void runScan(homeUrl);
  };
  const startNew = () => { setInput(''); setInputKind('message'); setResult(null); setAlertDismissed(false); setNotice(''); autoScanStartedFor.current = ''; navigateTo('scan'); };
  const count = history.length;
  const riskCounts = useMemo(() => ({ critical: history.filter(x => x.level === 'critical').length, high: history.filter(x => x.level === 'high').length, medium: history.filter(x => x.level === 'medium').length }), [history]);
  return <main className="app">
    <div className="ambient a1"/><div className="ambient a2"/><div className="ambient a3"/>
    {screen === 'welcome' && <section className="welcome-screen">
      <div className="welcome-topline"><span>ZXH OFFICIAL</span></div>
      <div className="welcome-visual"><div className="umbrella">◈</div><div className="hero-shield"><ShieldCheck size={36}/></div><Wave/></div>
      <div className="welcome-copy"><div className="micro-label">WELCOME TO ZXH OFFICIAL • DIGITAL PROTECTION SYSTEM</div><h1>CyberGuard<br/><em>Phishing Attack Shield</em></h1><p>Stay protected. Spot suspicious links and messages before they become a threat.</p></div>
      <button className="round-start" onClick={() => navigateTo('home')} aria-label="Enter CyberGuard"><ArrowRight/></button>
      <div className="welcome-credit">POWERED BY <b>ZXH OFFICIAL</b><small>CREATED BY ZULQARNAIN X HAIDER</small></div>
    </section>}
    {screen !== 'welcome' && <>
      <header className="app-header">
        <button className="brand-lockup" onClick={() => setScreen('home')}><span className="brand-symbol"><ShieldCheck size={19}/></span><span><b>ZXH <i>OFFICIAL</i></b><small>CYBERGUARD SHIELD</small></span></button>
        <div className="header-actions"><button className="icon-btn" aria-label="Notifications" onClick={() => setNotice('You are all caught up.')}><Bell size={18}/></button></div>
      </header>
      {screen === 'home' && <section className="dashboard page-in">
        <div className="greeting"><div><small>WELCOME BACK</small><h1>Cyber Defender</h1><p>Your digital safety overview</p></div><div className="avatar"><ShieldCheck/></div></div>
        <div className="home-link-box glass-panel">
          <div className="home-link-heading"><span className="summary-icon"><Link2/></span><div><b>Check a suspicious link</b><small>Paste a URL to scan for known threats</small></div></div>
          <label htmlFor="home-url">PASTE URL TO CHECK</label>
          <input id="home-url" className="home-url-input" type="url" inputMode="url" autoCapitalize="none" autoCorrect="off" value={homeUrl} onChange={e => setHomeUrl(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') runHomeUrlScan(); }} placeholder="https://example.com/verify"/>
          <button className="scan-button" onClick={runHomeUrlScan} disabled={!homeUrl.trim() || scanning}>{scanning ? 'OPENING SCANNER…' : 'CHECK LINK'} <ArrowRight size={17}/></button>
          {notice && <p className="notice">{notice}</p>}
        </div>
        <div className="score-panel">
          <div className="score-ring"><div><strong>{count}</strong><small>LINKS</small><span>Scanned & reviewed</span></div></div>
          <div className="score-caption"><span className="glow-dot"/> YOUR SECURITY ACTIVITY</div>
        </div>
        <div className="risk-grid">
          <div className="risk-tile critical"><span>Critical</span><b>{riskCounts.critical}</b><small>0% this week</small></div>
          <div className="risk-tile high"><span>High</span><b>{riskCounts.high}</b><small>Needs action</small></div>
          <div className="risk-tile medium"><span>Medium</span><b>{riskCounts.medium}</b><small>Stay alert</small></div>
        </div>
        <div className="section-title"><h2>Statistical Summary</h2><span>See all</span></div>
        <div className="summary-list">
          <div className="summary-row"><span className="summary-icon"><ScanLine/></span><span><b>Daily Scanned</b><small>Last 24 hours</small></span><strong>{history.length} Links</strong></div>
          <div className="summary-row"><span className="summary-icon"><Clock3/></span><span><b>Weekly Scanned</b><small>Last 7 days</small></span><strong>{history.length} Links</strong></div>
          <div className="summary-row"><span className="summary-icon"><TrendingUp/></span><span><b>Monthly Scanned</b><small>Last 30 days</small></span><strong>{count} Links</strong></div>
        </div>
      </section>}
      {screen === 'scan' && <section className="scan-page page-in">
        <button className="scanner-back" onClick={() => window.history.state?.zxhScreen ? window.history.back() : navigateTo('home')}><ArrowLeft size={15}/> BACK</button>
        <div className="scan-heading"><div className="scan-emblem"><ShieldCheck size={27}/></div><h1>Security Scanner</h1><p>Analyse a suspicious link or message</p></div>
        <Wave className="scan-wave"/>
        <div className="scan-form glass-panel">
          <div className="message-mode-label"><MessageSquareText size={16}/> LINK &amp; MESSAGE THREAT ANALYSER</div>
          <label>PASTE LINK OR MESSAGE HERE</label>
          <textarea value={input} onChange={e => { const v=e.target.value; setInput(v); setInputKind(detectContentType(v)); setResult(null); setNotice(''); autoScanStartedFor.current = ''; if (autoScanTimer.current !== null) window.clearTimeout(autoScanTimer.current); }} placeholder="Paste a URL or suspicious SMS / WhatsApp message…" rows={3}/>
          <div className={"detected-type " + inputKind}><span className="detected-type-pulse"/><b>{inputKind === "url" ? "WEBSITE / URL DETECTED" : inputKind === "message_with_link" ? "TEXT MESSAGE + LINK DETECTED" : "TEXT MESSAGE DETECTED"}</b><small>{inputKind === "url" ? "Website reputation scanner selected" : inputKind === "message_with_link" ? "Message scanner selected • embedded link noticed" : "Message threat scanner selected"}</small></div><div className="input-meta"><span><LockKeyhole size={12}/> Auto-detection selects the correct scanner</span><span>{input.length} chars</span></div>
          <button className="scan-button" onClick={() => void runScan()} disabled={!input.trim() || scanning}>{scanning ? "SCANNING…" : "SCAN LINK / MESSAGE"} <ArrowRight size={17}/></button>
          {notice && <p className="notice">{notice}</p>}
        </div>
        {scanning && <div ref={radarRef} className="scan-progress-anchor"><RadarScanner/></div>}
        {result && <div className="result-area page-in">
          <div className="section-title"><h2>Threat Analysis Report</h2><span>JUST NOW</span></div>
          {(result.level === "critical" || result.level === "high") && !alertDismissed && <div className="zxh-alert-backdrop" role="presentation" onClick={e => { if (e.target === e.currentTarget) setAlertDismissed(true); }}><section className="zxh-alert-modal" role="alertdialog" aria-modal="true" aria-labelledby="zxh-alert-title"><button className="zxh-alert-close" aria-label="Close alert" onClick={() => setAlertDismissed(true)}><X size={21}/></button><div className="alert-flash"><span>⚠</span></div><div className="zxh-alert-brand">𖤍 ZXH OFFICIAL 𖤍</div><small className="zxh-alert-kicker">CYBERGUARD SECURITY WARNING</small><strong id="zxh-alert-title">THREAT ALERT</strong><b className="zxh-alert-risk">{result.level.toUpperCase()} RISK DETECTED</b><p>{result.findings.length} suspicious indicator(s) found. Do not open the link or share passwords, OTPs or payment details.</p><div className="zxh-alert-owner">PROTECTED BY <b>ZXH OFFICIAL</b><span>CREATED BY ZULQARNAIN X HAIDER</span></div><button className="zxh-alert-action" onClick={() => { setAlertDismissed(true); window.setTimeout(() => document.querySelector(".result-card")?.scrollIntoView({behavior:"smooth",block:"start"}), 80); }}>VIEW FULL REPORT <ArrowRight size={17}/></button></section></div>}<div className="result-card glass-panel">
            <div className="result-signal"><div className="result-signal-icon"><ShieldCheck size={25}/></div><div><span>ZXH OFFICIAL • THREAT ANALYSIS</span><b>SCAN COMPLETED</b></div><i className={'result-level-dot ' + result.level}/></div><div className="scanned-target"><small>{result.contentType === "url" ? "SCANNED WEBSITE / URL" : result.contentType === "message_with_link" ? "SCANNED TEXT MESSAGE • LINK FOUND" : "SCANNED TEXT MESSAGE"}</small><span>{result.value}</span><em className="content-type-chip">{result.contentType === "url" ? "URL SCAN" : result.contentType === "message_with_link" ? "MESSAGE + LINK SCAN" : "MESSAGE SCAN"}</em></div>
            {result.pageAnalysis && <div className="page-intel">
              <div className="page-intel-head"><b>DEEP WEBSITE CONTENT INSPECTION</b><span>{result.pageAnalysis.status === 'inspected' ? 'HTML INSPECTED' : 'PARTIAL CHECK'}</span></div>
              {result.pageAnalysis.title && <div className="page-intel-field"><small>PAGE TITLE</small><strong>{result.pageAnalysis.title}</strong></div>}
              {result.pageAnalysis.description && <div className="page-intel-field"><small>META DESCRIPTION</small><p>{result.pageAnalysis.description}</p></div>}
              {!!result.pageAnalysis.keywords?.length && <div className="page-intel-field"><small>META KEYWORDS</small><p>{result.pageAnalysis.keywords.join(' • ')}</p></div>}
              {!!result.pageAnalysis.visibleTextPreview && <div className="page-intel-field"><small>VISIBLE TEXT PREVIEW</small><p>{result.pageAnalysis.visibleTextPreview}</p></div>}
              {!!result.pageAnalysis.findings?.length && <div className="page-intel-field"><small>CONTENT INDICATORS</small><p>{result.pageAnalysis.findings.length} content indicator(s) detected and included in the risk report.</p></div>}
              {!!result.pageAnalysis.forms?.length && <div className="page-intel-field"><small>FORM DESTINATIONS</small>{result.pageAnalysis.forms.map((url,i)=><a key={i} href={url} target="_blank" rel="noopener noreferrer">{url}</a>)}</div>}
              {!!result.pageAnalysis.links?.length && <div className="page-intel-field"><small>PAGE LINKS ({result.pageAnalysis.links.length})</small>{result.pageAnalysis.links.slice(0,8).map((url,i)=><a key={i} href={url} target="_blank" rel="noopener noreferrer">{url}</a>)}</div>}
              <div className="page-intel-foot">Inspected {result.pageAnalysis.contentLength || 0} HTML characters • Forms are never submitted • Page scripts are never executed</div>
            </div>}
            <div className={'verdict ' + result.level}><span className="verdict-icon"><CircleAlert size={19}/></span><div><b>{result.verdict}</b><small>{result.level.toUpperCase()} RISK INDICATORS</small></div></div>
            <div className="finding-list">{result.findings.map((f,i) => <div className="finding" key={i}><span>•</span><div><b>{f.title}</b><p>{f.detail}</p></div></div>)}</div>
            {result.domainRegistration ? <div className="domain-intel"><b>DOMAIN REGISTRATION INTELLIGENCE</b><span><strong>{result.domainRegistration.domain}</strong></span>{result.domainRegistration.status === 'found' ? <><span>Registration: {result.domainRegistration.registeredAt ? new Date(result.domainRegistration.registeredAt).toLocaleDateString() : 'Date not published'}</span><span>Domain age: {typeof result.domainRegistration.ageDays === 'number' ? result.domainRegistration.ageDays + ' days' : 'Not disclosed'}</span>{result.domainRegistration.registrar ? <span>Registrar: {result.domainRegistration.registrar}</span> : null}</> : <span className="source-off">Registration details {result.domainRegistration.status === 'not_found' ? 'not found' : 'unavailable'} from RDAP.</span>}</div> : null}
            {(result.checkedSources?.length || result.unavailableSources?.length) ? <div className="source-coverage"><b>THREAT FEED COVERAGE</b>{result.checkedSources?.map(name => <span className="source-ok" key={name}>✓ {name} — checked</span>)}{result.unavailableSources?.map(name => <span className="source-off" key={name}>! {name} — unavailable</span>)}</div> : null}
            <button className="scan-button" onClick={startNew}>CHECK AGAIN <ArrowRight size={17}/></button>
          </div>
          <p className="disclaimer"><Shield size={14}/> A feed no-match or low-risk pattern result does not prove a link or message is safe.</p>
        </div>}
      </section>}
      {screen === 'history' && <section className="simple-page page-in"><div className="page-title"><small>YOUR ACTIVITY</small><h1>Scan History</h1><p>Recent checks on this device</p></div>{history.length ? history.map((item,i)=><div className="history-item" key={i}><span className={'history-dot ' + item.level}/><div><b>{item.verdict}</b><small>{item.value.slice(0,55)}</small></div><ChevronRight/></div>) : <div className="empty-state"><History size={32}/><b>No scans yet</b><p>Your recent link checks will appear here.</p><button onClick={() => navigateTo('scan')}>Start scanning</button></div>}</section>}
      {screen === 'settings' && <section className="simple-page page-in"><div className="page-title"><small>APP PREFERENCES</small><h1>Settings</h1><p>Privacy and app information</p></div><div className="settings-card"><ShieldCheck/><div><b>Local privacy mode</b><small>Message text is sent to the ZXH message-analysis API for pattern checks and is not stored.</small></div><span className="on-pill">ON</span></div><div className="settings-card"><Bell/><div><b>Notifications</b><small>Notifications are not required for link scanning.</small></div></div><div className="settings-card"><LockKeyhole/><div><b>Security notice</b><small>This is not an official NCCIA or malware verification service.</small></div></div></section>}
      <nav className="bottom-nav"><button className={screen === 'home' ? 'active' : ''} onClick={() => setScreen('home')}><Home/><span>Home</span></button><button className={screen === 'scan' ? 'active' : ''} onClick={() => setScreen('scan')}><ScanLine/><span>Scan</span></button><button className={screen === 'history' ? 'active' : ''} onClick={() => navigateTo('history')}><History/><span>History</span></button><button className={screen === 'settings' ? 'active' : ''} onClick={() => navigateTo('settings')}><Settings/><span>Settings</span></button></nav>
      <footer className="site-credit">
        <b>ZXH OFFICIAL</b><span>CREATED BY ZULQARNAIN X HAIDER</span>
        <div className="footer-links" aria-label="Official ZXH links">
          <a href="https://whatsapp.com/channel/0029Vb6lszR7YSd3iYfa2V0n" target="_blank" rel="noopener noreferrer">WhatsApp Channel</a>
          <a href="https://t.me/zxh_official786" target="_blank" rel="noopener noreferrer">Telegram</a>
          <a href="https://zxh-official-tools.pages.dev/" target="_blank" rel="noopener noreferrer">Tools Hub</a>
          <a href="https://zxh-official-mods.pages.dev/" target="_blank" rel="noopener noreferrer">Mods</a>
          <a href="https://zxh-all-media-downloader.pages.dev/" target="_blank" rel="noopener noreferrer">Media Downloader</a>
          <a href="https://zxh-official-portfolio.pages.dev/" target="_blank" rel="noopener noreferrer">Portfolio</a>
          <a href="https://whatsapp.com/channel/0029Vb8XF2y1NCrQDWetrk1r" target="_blank" rel="noopener noreferrer">WhatsApp Backup</a>
        </div>
        <small className="footer-disclaimer">Threat-feed matches and URL pattern checks are indicators, not a guarantee of safety.</small>
      </footer>
    </>}
  </main>;
}
export default App;
