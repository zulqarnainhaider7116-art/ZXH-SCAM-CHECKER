import { useMemo, useState } from 'react';
import {
  ArrowLeft, ArrowRight, Bell, Check, ChevronRight, CircleAlert, Clock3,
  Globe2, History, Home, Link2, LockKeyhole, MessageSquareText, ScanLine,
  Settings, Shield, ShieldAlert, ShieldCheck, Sparkles, TrendingUp, X
} from 'lucide-react';

type Screen = 'welcome' | 'home' | 'scan' | 'history' | 'settings';
type Finding = { level: 'critical' | 'high' | 'medium' | 'low'; title: string; detail: string };
type Result = { verdict: string; level: Finding['level']; findings: Finding[]; value: string };

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

function Wave({ className = '' }: { className?: string }) {
  return <svg className={'wave ' + className} viewBox="0 0 700 230" preserveAspectRatio="none" aria-hidden="true">
    <defs><linearGradient id="waveGreen" x1="0" x2="1"><stop stopColor="#00f5a0" stopOpacity="0"/><stop offset=".48" stopColor="#00e6ad"/><stop offset="1" stopColor="#00aaff" stopOpacity=".1"/></linearGradient><linearGradient id="waveBlue" x1="0" x2="1"><stop stopColor="#007dff" stopOpacity="0"/><stop offset=".5" stopColor="#00caff"/><stop offset="1" stopColor="#36e8ff" stopOpacity="0"/></linearGradient></defs>
    <path d="M-20 130 C120 20 180 220 330 100 S520 30 730 130" stroke="url(#waveGreen)" strokeWidth="2" fill="none"/><path d="M-20 160 C140 45 190 240 350 125 S550 55 730 150" stroke="url(#waveBlue)" strokeWidth="3" fill="none"/><path d="M-20 180 C120 75 240 250 390 145 S580 90 730 180" stroke="#00baff" strokeOpacity=".35" strokeDasharray="3 7" fill="none"/>
  </svg>;
}

function App() {
  const [screen, setScreen] = useState<Screen>('welcome');
  const [mode, setMode] = useState<'link' | 'message'>('link');
  const [input, setInput] = useState('');
  const [homeUrl, setHomeUrl] = useState('');
  const [homeResult, setHomeResult] = useState<Result | null>(null);
  const [homeScanning, setHomeScanning] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [history, setHistory] = useState<Result[]>([]);
  const [notice, setNotice] = useState('');
  const [scanning, setScanning] = useState(false);
  const runScan = async () => {
    if (!input.trim()) { setNotice('Paste a message first.'); return; }
    setScanning(true);
    try {
      const response = await fetch('/api/check-message', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message: input.trim() }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'Message scan failed.');
      const next: Result = { verdict: data.verdict, level: data.level, findings: data.findings, value: input.trim() };
      setResult(next); setHistory(old => [next, ...old].slice(0, 8)); setNotice('');
    } catch (error) { setNotice(error instanceof Error ? error.message : 'Could not reach message scanner.'); }
    finally { setScanning(false); }
  };
  const runHomeUrlScan = async () => {
    if (!homeUrl.trim()) { setNotice('Paste a URL first.'); return; }
    setHomeScanning(true); setNotice('');
    try {
      const response = await fetch('/api/check-url', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: homeUrl.trim() }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'URL check failed.');
      const local = inspect(homeUrl.trim());
      const findings: Finding[] = Array.isArray(data.findings) ? [...data.findings] : [];
      if (data.status === 'malicious') findings.unshift({ level: 'critical', title: 'Threat intelligence match', detail: 'This URL matched a known malicious URL feed. Do not open it.' });
      else if (data.status === 'not_listed') findings.unshift({ level: 'low', title: 'No threat-feed match found', detail: 'The checked feeds did not list this URL. This is not proof that it is safe.' });
      else findings.unshift({ level: 'medium', title: 'Live reputation lookup unavailable', detail: data.message || 'The external threat feed could not be checked.' });
      findings.push(...local.findings);
      const next: Result = { value: homeUrl.trim(), level: data.status === 'malicious' ? 'critical' : local.level, verdict: data.status === 'malicious' ? 'Known malicious URL detected' : data.status === 'not_listed' ? 'No match found — stay cautious' : 'Reputation check incomplete', findings };
      setHomeResult(next); setHistory(old => [next, ...old].slice(0, 8));
    } catch (error) { setNotice(error instanceof Error ? error.message : 'Could not reach URL scanner.'); }
    finally { setHomeScanning(false); }
  };
  const startNew = () => { setInput(''); setResult(null); setScreen('scan'); };
  const count = history.length;
  const riskCounts = useMemo(() => ({ critical: history.filter(x => x.level === 'critical').length, high: history.filter(x => x.level === 'high').length, medium: history.filter(x => x.level === 'medium').length }), [history]);
  return <main className="app">
    <div className="ambient a1"/><div className="ambient a2"/><div className="ambient a3"/>
    {screen === 'welcome' && <section className="welcome-screen">
      <div className="welcome-topline"><span>ZXH OFFICIAL</span><span className="top-pulse"/></div>
      <div className="welcome-visual"><div className="umbrella">◈</div><div className="hero-shield"><ShieldCheck size={36}/></div><Wave/></div>
      <div className="welcome-copy"><div className="micro-label">WELCOME TO ZXH OFFICIAL • DIGITAL PROTECTION SYSTEM</div><h1>CyberGuard<br/><em>Phishing Attack Shield</em></h1><p>Stay protected. Spot suspicious links and messages before they become a threat.</p></div>
      <button className="round-start" onClick={() => setScreen('home')} aria-label="Enter CyberGuard"><ArrowRight/></button>
      <div className="welcome-credit">POWERED BY <b>ZXH OFFICIAL</b><small>CREATED BY ZULQARNAIN X HAIDER</small></div>
    </section>}
    {screen !== 'welcome' && <>
      <header className="app-header">
        <button className="brand-lockup" onClick={() => setScreen('home')}><span className="brand-symbol"><ShieldCheck size={19}/></span><span><b>ZXH <i>OFFICIAL</i></b><small>CYBERGUARD SHIELD</small></span></button>
        <button className="icon-btn" aria-label="Notifications" onClick={() => setNotice('You are all caught up.')}><Bell size={18}/></button>
      </header>
      {screen === 'home' && <section className="dashboard page-in">
        <div className="greeting"><div><small>WELCOME BACK</small><h1>Cyber Defender</h1><p>Your digital safety overview</p></div><div className="avatar"><ShieldCheck/></div></div>
        <div className="quick-status"><span className="status-orb"><Shield size={17}/></span><span>Protection status <b>Scanner ready</b></span><span className="status-live">● CHECKS AVAILABLE</span></div>
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
        <div className="home-link-box glass-panel">
          <div className="home-link-heading"><span className="summary-icon"><Link2/></span><div><b>Check a suspicious link</b><small>Live threat-feed reputation lookup</small></div></div>
          <label htmlFor="home-url">PASTE URL TO CHECK</label>
          <input id="home-url" className="home-url-input" type="url" inputMode="url" autoCapitalize="none" autoCorrect="off" value={homeUrl} onChange={e => setHomeUrl(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') runHomeUrlScan(); }} placeholder="https://example.com/verify"/>
          <button className="scan-button" onClick={runHomeUrlScan} disabled={!homeUrl.trim() || homeScanning}>{homeScanning ? 'CHECKING URL…' : 'CHECK LINK NOW'} <ArrowRight size={17}/></button>
          {notice && <p className="notice">{notice}</p>}
        </div>
        {homeResult && <div className="result-area page-in"><div className="section-title"><h2>URL Check Result</h2><span>JUST NOW</span></div>
          <div className="result-card glass-panel"><div className={'verdict ' + homeResult.level}><span className="verdict-icon"><CircleAlert size={19}/></span><div><b>{homeResult.verdict}</b><small>{homeResult.level.toUpperCase()} RISK INDICATORS</small></div></div>
            <div className="finding-list">{homeResult.findings.map((f,i) => <div className="finding" key={i}><span>•</span><div><b>{f.title}</b><p>{f.detail}</p></div></div>)}</div>
            <button className="scan-button" onClick={() => { setHomeUrl(''); setHomeResult(null); }}>CHECK ANOTHER LINK <ArrowRight size={17}/></button>
          </div><p className="disclaimer"><Shield size={14}/> A feed no-match is not a safety guarantee.</p>
        </div>}
      </section>}
      {screen === 'scan' && <section className="scan-page page-in">
        <div className="scan-heading"><div className="scan-emblem"><ShieldCheck size={27}/></div><h1>Check Links</h1><p>Scan a suspicious URL or message</p></div>
        <Wave className="scan-wave"/>
        <div className="scan-form glass-panel">
          <div className="message-mode-label"><MessageSquareText size={16}/> MESSAGE THREAT ANALYSER</div>
          <label>PASTE MESSAGE HERE</label>
          <textarea value={input} onChange={e => setInput(e.target.value)} placeholder="Paste suspicious SMS or WhatsApp message…" rows={3}/>
          <div className="input-meta"><span><LockKeyhole size={12}/> Message sent to ZXH analysis API; not stored</span><span>{input.length} chars</span></div>
          <button className="scan-button" onClick={runScan} disabled={!input.trim() || scanning}>{scanning ? "ANALYSING MESSAGE…" : "ANALYSE MESSAGE"} <ArrowRight size={17}/></button>
          {notice && <p className="notice">{notice}</p>}
        </div>
        {result && <div className="result-area page-in">
          <div className="section-title"><h2>Message Scan Result</h2><span>JUST NOW</span></div>
          <div className="result-card glass-panel">
            <div className="earth-visual"><div className="earth-glow"/><span>CYBERGUARD • ZXH</span></div>
            <div className={'verdict ' + result.level}><span className="verdict-icon"><CircleAlert size={19}/></span><div><b>{result.verdict}</b><small>{result.level.toUpperCase()} RISK INDICATORS</small></div></div>
            <div className="finding-list">{result.findings.map((f,i) => <div className="finding" key={i}><span>•</span><div><b>{f.title}</b><p>{f.detail}</p></div></div>)}</div>
            <button className="scan-button" onClick={startNew}>CHECK AGAIN <ArrowRight size={17}/></button>
          </div>
          <p className="disclaimer"><Shield size={14}/> Basic pattern-based review only. A low-risk result does not prove a link is safe.</p>
        </div>}
      </section>}
      {screen === 'history' && <section className="simple-page page-in"><div className="page-title"><small>YOUR ACTIVITY</small><h1>Scan History</h1><p>Recent checks on this device</p></div>{history.length ? history.map((item,i)=><div className="history-item" key={i}><span className={'history-dot ' + item.level}/><div><b>{item.verdict}</b><small>{item.value.slice(0,55)}</small></div><ChevronRight/></div>) : <div className="empty-state"><History size={32}/><b>No scans yet</b><p>Your recent link checks will appear here.</p><button onClick={() => setScreen('scan')}>Start scanning</button></div>}</section>}
      {screen === 'settings' && <section className="simple-page page-in"><div className="page-title"><small>APP PREFERENCES</small><h1>Settings</h1><p>Privacy and app information</p></div><div className="settings-card"><ShieldCheck/><div><b>Local privacy mode</b><small>Message text is sent to the ZXH message-analysis API for pattern checks and is not stored.</small></div><span className="on-pill">ON</span></div><div className="settings-card"><Bell/><div><b>Notifications</b><small>Notifications are not required for link scanning.</small></div></div><div className="settings-card"><LockKeyhole/><div><b>Security notice</b><small>This is not an official NCCIA or malware verification service.</small></div></div></section>}
      <nav className="bottom-nav"><button className={screen === 'home' ? 'active' : ''} onClick={() => setScreen('home')}><Home/><span>Home</span></button><button className={screen === 'scan' ? 'active' : ''} onClick={() => setScreen('scan')}><ScanLine/><span>Scan</span></button><button className={screen === 'history' ? 'active' : ''} onClick={() => setScreen('history')}><History/><span>History</span></button><button className={screen === 'settings' ? 'active' : ''} onClick={() => setScreen('settings')}><Settings/><span>Settings</span></button></nav>
      <footer className="site-credit"><b>ZXH OFFICIAL</b><span>CREATED BY ZULQARNAIN X HAIDER</span></footer>
    </>}
  </main>;
}
export default App;
