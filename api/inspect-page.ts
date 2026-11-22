type Level = "critical" | "high" | "medium" | "low";
type Finding = { level: Level; title: string; detail: string; evidence?: string[] };
const MAX_BYTES = 1_200_000;
const UA = "Mozilla/5.0 (compatible; ZXH-Official-SecurityScanner/1.0)";
function publicHttp(value:string) {
  try {
    const u=new URL(value); if(!["http:","https:"].includes(u.protocol) || u.username || u.password) return false;
    const h=u.hostname.toLowerCase().replace(/^\[|\]$/g,"");
    if(!h || h==="localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return false;
    if(/^(127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h)) return false;
    if(h==="::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80:")) return false;
    return true;
  } catch { return false; }
}
function decode(s:string) { return s.replace(/&nbsp;/gi," ").replace(/&amp;/gi,"&").replace(/&quot;/gi,'"').replace(/&#39;|&apos;/gi,"'").replace(/&lt;/gi,"<").replace(/&gt;/gi,">").replace(/&#(\d+);/g,(_,n)=>String.fromCodePoint(Math.min(0x10ffff,Number(n)))).replace(/&#x([0-9a-f]+);/gi,(_,n)=>String.fromCodePoint(parseInt(n,16))); }
function plain(html:string) {
 return decode(html.replace(/<(script|style|noscript|svg|template)\b[^>]*>[\s\S]*?<\/\1\s*>/gi," ").replace(/<!--[\s\S]*?-->/g," ").replace(/<[^>]+>/g," ").replace(/\s+/g," ")).trim();
}
function meta(html:string,name:string) {
 const tags=html.match(/<meta\b[^>]*>/gi)||[];
 for(const tag of tags){
  const n=tag.match(/\b(?:name|property)\s*=\s*["']([^"']+)["']/i)?.[1];
  const c=tag.match(/\bcontent\s*=\s*["']([^"']*)["']/i)?.[1];
  if(n?.toLowerCase()===name.toLowerCase() && c!==undefined)return decode(c);
 }
 return "";
}
function inspectText(text:string, base:URL, links:string[], forms:string[], iframeCount:number) {
 const findings:Finding[]=[]; const add=(level:Level,title:string,detail:string,evidence:string[]=[] )=>findings.push({level,title,detail,evidence:evidence.slice(0,5)});
 const checks:Array<[RegExp,Level,string,string]>=[
 [/(?:free|instant|unlimited|get|claim)\s*(?:instagram\s*)?(?:followers?|likes?|views?|subscribers?)/i,"high","Fake followers / engagement bait","Free follower claims commonly lead to fake login, survey or payment traps."],
 [/(?:free|claim|get|unlimited|bonus)\s*(?:internet|mobile\s*data|data\s*pack|mbs?|gb|4g|5g)|(?:internet|data)\s*(?:free|offer|reward)/i,"high","Free internet / MBs bait","Unexpected free-data claims can imitate mobile operators and collect phone numbers or account details."],
 [/(?:free|claim|get|win|exclusive)\s*(?:gift|giveaway|prize|reward|voucher|cash|money)/i,"medium","Free money / reward bait","Reward claims are frequently used to harvest personal data or demand fake processing fees."],
 [/(?:\b(?:13,?000|13000)\s*(?:rs|rupees|pkr)?\b|نواز\s*شریف.{0,50}(?:روپے|ہزار|رقم)|(?:روپے|ہزار).{0,40}(?:دے\s*رہا|ملیں\s*گے|مل\s*رہے))/i,"high","Government / political cash claim","Unverified cash-payment claims using public figures or government names need independent confirmation."],
 [/(?:control\s*(?:your\s*)?(?:mobile|phone|device).{0,50}browser|mobile\s*control|remote\s*access|device\s*control|browser\s*monitoring|موبائل\s*کنٹرول)/i,"high","Remote mobile-control wording","This wording may describe remote-control software or a deceptive permission lure. Inspect the actual requested permissions."],
 [/(?:microphone|camera|clipboard|sms|contacts|accessibility\s*service|screen\s*sharing|notification\s*access)/i,"medium","Sensitive device capability mentioned","A page mentioning sensitive device capabilities deserves scrutiny; wording alone does not prove access was granted."],
 [/(?:enter|submit|verify|confirm).{0,35}(?:password|otp|pin|cvv|bank|card)|(?:password|otp|pin|cvv).{0,35}(?:verify|claim|reward|login)/i,"critical","Credential / OTP collection wording","The page appears to request credentials or one-time codes. Do not submit secrets through an unverified page."],
 [/(?:processing\s*fee|registration\s*fee|advance\s*fee|send\s*money|easypaisa|jazzcash|فیس\s*جمع|رقم\s*بھیجیں)/i,"high","Payment / fee request wording","Payment or fee language combined with a reward or claim may indicate an advance-fee scam."]
 ];
 for(const [re,level,title,detail] of checks){const m=text.match(re);if(m)add(level,title,detail,[m[0]]);}
 const host=base.hostname.toLowerCase();
 if(links.length){const suspicious=links.filter(x=>{try{const u=new URL(x);return u.hostname!==host && !u.hostname.endsWith("."+host)}catch{return true}});if(suspicious.length)add("medium","External destinations found","The page contains links to other domains. Review each destination before opening.",suspicious.slice(0,5));}
 if(forms.length)add("medium","HTML forms detected","The page contains forms. A form may collect information; this scanner does not submit forms.",forms.slice(0,5));
 if(iframeCount)add("medium","Embedded frames detected","Embedded frames can load third-party content. Their contents are not executed or fully inspected.",[iframeCount+" iframe(s)"]);
 return findings;
}
async function readLimited(response:Response) {
 const reader=response.body?.getReader(); if(!reader)return "";
 const chunks:Uint8Array[]=[];let size=0;
 while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>MAX_BYTES){await reader.cancel();throw new Error("PAGE_TOO_LARGE");}chunks.push(value);}
 const all=new Uint8Array(size);let offset=0;for(const c of chunks){all.set(c,offset);offset+=c.length;}
 return new TextDecoder("utf-8",{fatal:false}).decode(all);
}
export default async function handler(req:any,res:any) {
 res.setHeader("Cache-Control","no-store");res.setHeader("X-Content-Type-Options","nosniff");
 if(req.method!=="POST")return res.status(405).json({status:"error",message:"Use POST."});
 const raw=typeof req.body?.url==="string"?req.body.url.trim():"";
 if(!publicHttp(raw))return res.status(400).json({status:"error",message:"Enter a public HTTP or HTTPS URL."});
 let current=new URL(raw), html="", response:Response|undefined;
 try{
  for(let i=0;i<5;i++){
   if(!publicHttp(current.toString()))throw new Error("UNSAFE_REDIRECT");
   response=await fetch(current.toString(),{method:"GET",redirect:"manual",headers:{"User-Agent":UA,Accept:"text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"},signal:AbortSignal.timeout(8500)});
   if([301,302,303,307,308].includes(response.status)){
    const loc=response.headers.get("location");if(!loc)break;
    current=new URL(loc,current);if(i===4)throw new Error("TOO_MANY_REDIRECTS");continue;
   }
   break;
  }
  if(!response)throw new Error("NO_RESPONSE");
  if(!response.ok)throw new Error("HTTP_"+response.status);
  const type=response.headers.get("content-type")||"";
  if(!/text\/html|application\/xhtml\+xml/i.test(type))throw new Error("NOT_HTML");
  html=await readLimited(response);
 }catch(e){
  const reason=e instanceof Error?e.message:"FETCH_FAILED";
  return res.status(200).json({status:"partial",finalUrl:current.toString(),pageAnalysis:{status:"unavailable",title:"",description:"",keywords:[],visibleTextPreview:"",links:[],forms:[],findings:[{level:"medium",title:"Page content could not be inspected",detail:reason==="PAGE_TOO_LARGE"?"The page exceeded the 1.2 MB inspection limit.":reason==="UNSAFE_REDIRECT"?"A redirect pointed to a non-public or unsafe destination.":"The site blocked inspection, timed out, or did not return an HTML page."}],contentLength:0}});
 }
 const title=decode(html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1]||"").replace(/\s+/g," ").trim().slice(0,240);
 const description=meta(html,"description").slice(0,500);
 const keywords=meta(html,"keywords").split(/[,،;]/).map(x=>x.trim()).filter(Boolean).slice(0,30);
 const visibleText=plain(html).slice(0,12000);
 const linkMatches=[...html.matchAll(/<a\b[^>]*href=["']([^"'#]+)["'][^>]*>/gi)].slice(0,100);
 const links=linkMatches.map(m=>{try{return new URL(decode(m[1]),current).toString()}catch{return ""}}).filter(Boolean);
 const forms=[...html.matchAll(/<form\b[^>]*action=["']?([^"'\s>]*)/gi)].slice(0,20).map(m=>{try{return new URL(decode(m[1]||current.toString()),current).toString()}catch{return current.toString()}});
 const iframeCount=(html.match(/<iframe\b/gi)||[]).length;
 const combined=[title,description,keywords.join(" "),visibleText,links.join(" "),forms.join(" ")].join(" ");
 const findings=inspectText(combined,current,links,forms,iframeCount);
 const pageAnalysis={status:"inspected",finalUrl:current.toString(),title,description,keywords,visibleTextPreview:visibleText.slice(0,1800),links:links.slice(0,20),forms:forms.slice(0,10),iframeCount,findings,contentLength:html.length};
 return res.status(200).json({status:"inspected",pageAnalysis});
}