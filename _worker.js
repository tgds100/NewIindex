// SuperEdge金丝雀 v1.9.3 - 可部署文件
var CFG={id:"381e284f-a9d8-4829-b279-348f187a4e87",panelKey:"zw995mqy",panelPin:"ajy9k38g",maxED:8*1024,concur:1,directLoserTimeout:1500,failTTL:3e4,failCacheMax:128,maxStages:5,dnStall:3e4,memBudget:96*1024*1024,minPerSession:4*1024*1024,pathPrefix:["/api/v1/chat","/api/v2beta/events","/telemetry/ingest","/push/gateway"]};var PROFILES={default:{chunk:64*1024,dnPack:48*1024,dnTail:1024,dnQr:3,lowLat:false,upPack:32*1024,dnHigh:6*1024*1024,dnLow:1.5*1024*1024,stagger:1e3,totalTimeout:6e3},lowLat:{chunk:32*1024,dnPack:8*1024,dnTail:256,dnQr:0,lowLat:true,upPack:8*1024,dnHigh:2*1024*1024,dnLow:512*1024,stagger:200,totalTimeout:3e3},highSpeed:{chunk:256*1024,dnPack:256*1024,dnTail:8*1024,dnQr:4,lowLat:false,upPack:64*1024,dnHigh:10*1024*1024,dnLow:2.5*1024*1024,stagger:1500,totalTimeout:12e3}};var LL_MAP={"0":"default","1":"lowLat","2":"highSpeed"};var ENC=new TextEncoder;var DEC=new TextDecoder;if(!/^[0-9a-fA-F-]{32,36}$/.test(CFG.id)){throw new Error("CFG.id \u672A\u8BBE\u7F6E\u6216\u683C\u5F0F\u9519\u8BEF\uFF08\u5E94\u4E3A\u6807\u51C6 UUID\uFF0C\u5982 12345678-1234-1234-1234-123456789abc\uFF09")}if(!CFG.panelPin||CFG.panelPin.length<8){throw new Error("CFG.panelPin \u5FC5\u987B \u22658 \u4F4D")}if(!CFG.panelKey){throw new Error("CFG.panelKey \u4E0D\u80FD\u4E3A\u7A7A")}if(!Array.isArray(CFG.pathPrefix)||!CFG.pathPrefix.length||CFG.pathPrefix.some(p=>typeof p!=="string"||!p.startsWith("/")||/[?#]/.test(p))){throw new Error("CFG.pathPrefix \u5FC5\u987B\u662F\u975E\u7A7A\u6570\u7EC4\uFF0C\u6BCF\u9879\u4E3A\u4EE5 / \u5F00\u5934\u4E14\u4E0D\u542B ? # \u7684\u5B57\u7B26\u4E32\uFF08? \u540E\u662F\u53C2\u6570\u4E32\uFF0C\u4E0D\u80FD\u5199\u8FDB\u8DEF\u5F84\uFF09")}import{connect}from"cloudflare:sockets";var S5_GREET_NOAUTH=new Uint8Array([5,1,0]);var S5_GREET_AUTH=new Uint8Array([5,2,0,2]);var HTTP_TAIL=ENC.encode("User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n");var hex=c=>(c>64?c+9:c)&15;var idB=new Uint8Array(16);for(let i=0,p=0,c,h2;i<16;i++){c=CFG.id.charCodeAt(p++);c===45&&(c=CFG.id.charCodeAt(p++));h2=hex(c);c=CFG.id.charCodeAt(p++);c===45&&(c=CFG.id.charCodeAt(p++));idB[i]=h2<<4|hex(c)}var matchID=c=>{for(let i=0;i<16;i++)if(c[1+i]!==idB[i])return false;return true};var addr=(t2,b)=>t2===1?`${b[0]}.${b[1]}.${b[2]}.${b[3]}`:t2===2?DEC.decode(b):`[${Array.from({length:8},(_,i)=>(b[i*2]<<8|b[i*2+1]).toString(16)).join(":")}]`;var parseAddr=(b,o,t2)=>{const l=t2===1?4:t2===2?b[o++]:t2===3?16:null;if(l===null)return null;const n=o+l;return n>b.length?null:{targetAddrBytes:b.subarray(o,n),dataOffset:n}};var relay=c=>{if(c.length<24||!matchID(c))return null;const o=19+c[17];if(o+3>c.length)return null;const cmd=c[o-1];const p=c[o]<<8|c[o+1];const t2=c[o+2];const a=parseAddr(c,o+3,t2);return a?{cmd,addrType:t2,...a,port:p}:null};var b64urlDecode=str=>{let b64=str.replace(/-/g,"+").replace(/_/g,"/");while(b64.length%4)b64+="=";const bin=atob(b64);const out=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)out[i]=bin.charCodeAt(i);return out};var parseAddressPort=seg=>{if(seg.startsWith("[")){const m=seg.match(/^\[(.+?)\]:(\d+)$/);return m?[m[1],+m[2]]:[seg.slice(1,-1),443]}const[a,p=443]=seg.split(":");return[a,+p]};var parseAuthHost=raw=>{let username,password,hostPart=raw;const at=raw.lastIndexOf("@");if(at!==-1){const authPart=raw.substring(0,at);hostPart=raw.substring(at+1);const colon=authPart.indexOf(":");if(colon!==-1){username=authPart.substring(0,colon);password=authPart.substring(colon+1)}else{username=authPart}}const[h2,p]=parseAddressPort(hostPart);const cfg={username,password,hostname:h2,port:p||1080};if(username){const ub=ENC.encode(username);const pb=ENC.encode(password??"");if(ub.length>255||pb.length>255){cfg._s5Invalid=true}else{const buf=new Uint8Array(3+ub.length+pb.length);buf[0]=1;buf[1]=ub.length;buf.set(ub,2);buf[2+ub.length]=pb.length;buf.set(pb,3+ub.length);cfg._s5Auth=buf}cfg._httpAuth=btoa(`${username}:${password??""}`)}return cfg};var parseProxyURL=raw=>{if(!raw)return null;const m=raw.match(/^(socks5?|https?):\/\/(.+)$/i);if(!m)return null;const cfg=parseAuthHost(m[2]);const scheme=m[1].toLowerCase();const type=scheme.includes("5")||scheme==="socks"?"S5":"H";return{type,cfg}};var parseIPv6Into=(s,buf,off)=>{let str=s.startsWith("[")?s.slice(1,-1):s;const dbl=str.indexOf("::");let head,tail;if(dbl>=0){head=str.slice(0,dbl).split(":").filter(Boolean);tail=str.slice(dbl+2).split(":").filter(Boolean)}else{head=str.split(":");tail=[]}const groups=[...head];while(groups.length<8-tail.length)groups.push("0");groups.push(...tail);for(let i=0;i<8;i++){const n=parseInt(groups[i]||"0",16);buf[off+i*2]=n>>8&255;buf[off+i*2+1]=n&255}};var buildS5Connect=(type,addressRemote,portRemote)=>{let len,hostBytes=null;if(type===1)len=10;else if(type===2){hostBytes=ENC.encode(addressRemote);len=7+hostBytes.length}else if(type===3)len=22;else throw new Error("Unsupported address type");const buf=new Uint8Array(len);buf[0]=5;buf[1]=1;buf[2]=0;let o=3;if(type===1){buf[o++]=1;const p=addressRemote.split(".");buf[o++]=+p[0];buf[o++]=+p[1];buf[o++]=+p[2];buf[o++]=+p[3]}else if(type===2){buf[o++]=3;buf[o++]=hostBytes.length;buf.set(hostBytes,o);o+=hostBytes.length}else{buf[o++]=4;parseIPv6Into(addressRemote,buf,o);o+=16}buf[o++]=portRemote>>8&255;buf[o++]=portRemote&255;return buf};async function s5Connect(addressType,addressRemote,portRemote,cfg){if(cfg._s5Invalid)throw new Error("S5 auth too long (>255)");const{username,hostname,port,_s5Auth}=cfg;const sock=connect({hostname,port});if(sock.opened)await sock.opened;const writer=sock.writable.getWriter();const reader=sock.readable.getReader();try{await writer.write(username?S5_GREET_AUTH:S5_GREET_NOAUTH);let resp=(await reader.read()).value;if(!resp||resp[1]===255)throw new Error("S5 method rejected");if(resp[1]===2){if(!_s5Auth)throw new Error("S5 requires auth");await writer.write(_s5Auth);resp=(await reader.read()).value;if(!resp||resp[1]!==0)throw new Error("S5 auth failed")}else if(resp[1]!==0){throw new Error("S5 method not accepted")}await writer.write(buildS5Connect(addressType,addressRemote,portRemote));resp=(await reader.read()).value;if(!resp||resp[1]!==0)throw new Error("S5 connect failed");return sock}catch(err){try{sock.close()}catch{}throw err}finally{try{writer.releaseLock()}catch{}try{reader.releaseLock()}catch{}}}var findHeaderEnd=buf=>{for(let i=0;i+3<buf.length;i++){if(buf[i]===13&&buf[i+1]===10&&buf[i+2]===13&&buf[i+3]===10)return i+4}return-1};var PREFIX_MAP=new WeakMap;async function hTunnelConnect(addressType,addressRemote,portRemote,cfg){const{hostname,port,_httpAuth}=cfg;const sock=connect({hostname,port});if(sock.opened)await sock.opened;const target=`${addressRemote}:${portRemote}`;const head=`CONNECT ${target} HTTP/1.1\r
Host: ${target}\r
`+(_httpAuth?`Proxy-Authorization: Basic ${_httpAuth}\r
`:"");const headBytes=ENC.encode(head);const req=new Uint8Array(headBytes.length+HTTP_TAIL.length);req.set(headBytes);req.set(HTTP_TAIL,headBytes.length);const writer=sock.writable.getWriter();try{await writer.write(req)}finally{try{writer.releaseLock()}catch{}}const reader=sock.readable.getReader();let buf=new Uint8Array(0);let locked=true;try{for(;;){const{value,done}=await reader.read();if(done)throw new Error("Tunnel closed before response");const tmp=new Uint8Array(buf.length+value.length);tmp.set(buf);tmp.set(value,buf.length);buf=tmp;if(buf.length>65536)throw new Error("Tunnel response too large");const idx=findHeaderEnd(buf);if(idx<0)continue;const status=DEC.decode(buf.subarray(0,idx)).split("\r\n")[0];if(!/^HTTP\/1\.[01]\s+2\d\d/.test(status))throw new Error(`Tunnel refused: ${status}`);const leftover=buf.subarray(idx);locked=false;reader.releaseLock();if(leftover.byteLength)PREFIX_MAP.set(sock,leftover);return sock}}catch(err){if(locked){try{reader.releaseLock()}catch{}}try{sock.close()}catch{}throw err}}var sproutDirect=(h2,p)=>{const s=connect({hostname:h2,port:p});return s.opened?s.opened.then(()=>s):Promise.resolve(s)};var raceDirect=(h2,p,concur)=>{if(concur<=1)return sproutDirect(h2,p);const ts=Array(concur).fill().map(()=>sproutDirect(h2,p));return Promise.any(ts).then(w=>{for(const t2 of ts){if(t2===w)continue;t2.then(s=>{if(s!==w){try{s.close()}catch{}}},()=>{});Promise.race([t2.catch(()=>null),new Promise(r=>setTimeout(()=>r(null),CFG.directLoserTimeout))]).then(s=>{if(s&&s!==w){try{s.close()}catch{}}})}return w})};var sproutIP=async({address,port})=>{const s=connect({hostname:address,port});if(s.opened)await s.opened;return s};var raceHappy=(stages,staggerMs,totalTimeoutMs)=>{return new Promise((resolve,reject)=>{let settled=false;let failed=0;let nextIdx=0;let timer=0;let deadline=0;const cleanup=()=>{if(timer){clearTimeout(timer);timer=0}if(deadline){clearTimeout(deadline);deadline=0}};const finish=r=>{const s=r?.sock??r;if(settled){try{s?.close()}catch{}return}settled=true;cleanup();resolve(r)};const launch=()=>{if(settled)return;if(timer){clearTimeout(timer);timer=0}if(nextIdx>=stages.length)return;const idx=nextIdx++;stages[idx]().then(finish,()=>{if(settled)return;failed++;if(failed===stages.length){settled=true;cleanup();reject(new Error("all outbound stages failed"));return}launch()});if(nextIdx<stages.length)timer=setTimeout(launch,staggerMs)};deadline=setTimeout(()=>{if(settled)return;settled=true;cleanup();reject(new Error("happy-eyeballs timeout"))},totalTimeoutMs);launch()})};var connectWithTimeout=(fn,ms,label)=>{let timedOut=false;let timer=0;const p=Promise.resolve().then(fn).then(sock=>{if(timedOut){try{sock.close()}catch{}throw new Error(`${label} late arrival`)}return sock});const t2=new Promise((_,rej)=>{timer=setTimeout(()=>{timedOut=true;rej(new Error(`${label} timeout`))},ms)});return Promise.race([p,t2]).finally(()=>{if(timer)clearTimeout(timer)})};var FAIL_CACHE=new Map;var markFail=key=>{const now=Date.now();if(FAIL_CACHE.has(key))FAIL_CACHE.delete(key);else if(FAIL_CACHE.size>=CFG.failCacheMax){const first=FAIL_CACHE.keys().next().value;if(first!==void 0)FAIL_CACHE.delete(first)}FAIL_CACHE.set(key,now+CFG.failTTL)};var isFailed=key=>{const exp=FAIL_CACHE.get(key);if(!exp)return false;if(exp<Date.now()){FAIL_CACHE.delete(key);return false}return true};var connectToTarget=async(host,port,addressType,strategy)=>{const{globalGW,localSocks,localHttp,gwIP,concur,profile}=strategy;const{stagger,totalTimeout}=profile;if(globalGW){const fn=globalGW.type==="S5"?()=>s5Connect(addressType,host,port,globalGW.cfg):()=>hTunnelConnect(addressType,host,port,globalGW.cfg);return connectWithTimeout(fn,totalTimeout,"globalGW")}const key=`${host}:${port}`;const mkStage=(fn,via)=>()=>fn().then(sock=>({sock,via}));const directStage=mkStage(()=>raceDirect(host,port,concur),"direct");const backupStages=[];if(localSocks)backupStages.push(mkStage(()=>s5Connect(addressType,host,port,localSocks.cfg),"backup"));if(localHttp)backupStages.push(mkStage(()=>hTunnelConnect(addressType,host,port,localHttp.cfg),"backup"));if(gwIP)backupStages.push(mkStage(()=>sproutIP(gwIP),"backup"));if(!backupStages.length)return(await directStage()).sock;const ordered=isFailed(key)?[...backupStages,directStage]:[directStage,...backupStages];if(ordered.length>CFG.maxStages)ordered.length=CFG.maxStages;try{const{sock,via}=await raceHappy(ordered,stagger,totalTimeout);if(via==="direct")FAIL_CACHE.delete(key);else markFail(key);return sock}catch(err){markFail(key);throw err}};var VLESS_RESP_V0=new Uint8Array([0,0]);var VLESS_RESP_V1=new Uint8Array([1,0]);var activeSessions=0;var getSessionLimit=()=>Math.max(CFG.minPerSession,Math.floor(CFG.memBudget/Math.max(1,activeSessions)));var mkK=(cap,cpy=0)=>{let q=[],h2=0,b=0,buf=null;const e=()=>h2>=q.length;const trim=()=>{h2>32&&h2*2>=q.length&&(q=q.slice(h2),h2=0)};const clear=()=>{q=[];h2=0;b=0};const take=()=>{if(e())return null;const d=q[h2];q[h2++]=void 0;b-=d.byteLength;trim();return d};const sow=d=>{const n=d?.byteLength||0;return!n||(q.push(d),b+=n,1)};const pack=d=>{d||=take();if(!d||e())return[d,0];let n=d.byteLength,j=h2;while(j<q.length){const x=q[j],nn=n+x.byteLength;if(nn>cap)break;n=nn;j++}if(j===h2)return[d,0];const out=buf||=new Uint8Array(cap);out.set(d);for(let o=d.byteLength;h2<j;){const x=q[h2];q[h2++]=void 0;b-=x.byteLength;out.set(x,o);o+=x.byteLength}trim();const u=out.subarray(0,n);return[cpy?u.slice():u,1]};return{e,get b(){return b},clear,take,sow,pack}};var mkQ=cap=>{const k=mkK(cap);return{get empty(){return k.e()},get b(){return k.b},clear:k.clear,sow:k.sow,bundle:d=>k.pack(d)}};var mkDn=(w,profile)=>{const cap=profile.dnPack;const tail=profile.dnTail;const maxRetry=profile.dnQr;const lowLat=profile.lowLat;const low=Math.max(4096,tail*12);const k=mkK(cap,1);let tp=0,gen=0,qk=0,qr=0;const reap=()=>{tp&&clearTimeout(tp);tp=0;qr=0;for(;;){const[u]=k.pack();if(!u)break;w.send(u)}};const ripen=()=>{if(k.e()||tp)return;if(k.b>=cap||cap-k.b<tail)return reap();if(lowLat||maxRetry===0)return reap();tp=setTimeout(()=>{tp=0;if(k.e())return;if(k.b>=cap||cap-k.b<tail)return reap();if(qr<maxRetry&&(gen!==qk||k.b<low)){qr++;qk=gen;return ripen()}reap()},1)};return{send(u){let o=0,n=u?.byteLength||0;if(!n)return;while(o<n){const m=Math.min(cap-k.b,n-o);if(!m){reap();continue}k.sow(o||m!==n?u.subarray(o,o+m):u);gen++;o+=m;if(k.b>=cap||cap-k.b<tail)reap();else ripen()}},reap}};var drainDownstream=async(w,profile)=>{if(typeof w.bufferedAmount!=="number"||w.bufferedAmount<=profile.dnHigh)return;const t0=Date.now();let delay=1;while(w.bufferedAmount>profile.dnLow){if(w.readyState!==1)throw new Error("ws closed during drain");if(Date.now()-t0>CFG.dnStall)throw new Error("downstream stalled");await new Promise(r=>setTimeout(r,delay));delay=Math.min(delay*1.5,20)}};var mill=async(rd,w,profile)=>{const chunkSize=profile.chunk;const r=rd.getReader({mode:"byob"});const tx=mkDn(w,profile);let buf=new ArrayBuffer(chunkSize);try{for(;;){await drainDownstream(w,profile);const{done,value:v}=await r.read(new Uint8Array(buf,0,chunkSize));if(done)break;if(!v?.byteLength)continue;if(v.byteLength>=chunkSize>>1){tx.reap();w.send(v);buf=new ArrayBuffer(chunkSize)}else{tx.send(v.slice());buf=v.buffer}}tx.reap()}catch{}finally{try{tx.reap()}catch{}try{r.releaseLock()}catch{}}};var parseED=req=>{const raw=req.headers.get("sec-websocket-protocol")||"";if(!raw)return null;const list=raw.split(",").map(s=>s.trim()).filter(Boolean);for(const c of list){if(c.length>CFG.maxED*4/3+4)continue;try{const t2=b64urlDecode(c);if(t2.byteLength<=CFG.maxED)return t2}catch{}}return null};var runSession=(server,req,strategy)=>{activeSessions++;const ed=parseED(req);const profile=strategy.profile;const uq=mkQ(profile.upPack);let curW=null,sock=null,closed=false,busy=false;const wither=()=>{if(closed)return;closed=true;activeSessions--;uq.clear();try{curW?.releaseLock()}catch{}try{sock?.close()}catch{}try{server.close()}catch{}};const toU8=d=>d instanceof Uint8Array?d:ArrayBuffer.isView(d)?new Uint8Array(d.buffer,d.byteOffset,d.byteLength):new Uint8Array(d);const sow=d=>{const u=toU8(d),n=u.byteLength;if(!n)return 1;const limit=getSessionLimit();if(uq.b+n>limit){wither();return 0}if(uq.sow(u))return 1;wither();return 0};const thresh=async()=>{if(busy||closed)return;busy=true;try{for(;;){if(closed)break;if(!sock){const[d2]=uq.bundle();if(!d2)break;const r=relay(d2);if(!r){wither();break}const host=addr(r.addrType,r.targetAddrBytes);const port=r.port;if(r.cmd!==1){wither();break}server.send(d2[0]===0?VLESS_RESP_V0:d2[0]===1?VLESS_RESP_V1:new Uint8Array([d2[0],0]));const payload=d2.subarray(r.dataOffset);try{sock=await connectToTarget(host,port,r.addrType,strategy);if(closed){try{sock?.close()}catch{}sock=null;break}if(!sock){wither();break}const pfx=PREFIX_MAP.get(sock);if(pfx){PREFIX_MAP.delete(sock);try{server.send(pfx)}catch{}}curW=sock.writable.getWriter();if(payload?.byteLength)await curW.write(payload);mill(sock.readable,server,profile).finally(()=>wither())}catch{wither();break}continue}const[d]=uq.bundle();if(!d)break;try{await curW.write(d)}catch{wither();break}}}finally{busy=false;if(!closed&&!uq.empty)queueMicrotask(thresh)}};try{if(ed&&sow(ed))thresh();server.addEventListener("message",e=>{if(!closed&&sow(e.data))thresh()});server.addEventListener("close",wither);server.addEventListener("error",wither)}catch{wither()}};var DEFAULT_LANG="en";var LANGS=[{code:"en",htmlLang:"en",short:"EN"},{code:"zh",htmlLang:"zh-CN",short:"\u4E2D\u6587"},{code:"ja",htmlLang:"ja",short:"\u65E5\u672C\u8A9E"},{code:"ru",htmlLang:"ru",short:"RU"}];var MESSAGES={en:{"nav.docs":"Docs","nav.status":"Status","nav.about":"About","nav.privacy":"Privacy","footer.tagline":"Edge inference and telemetry","lang.aria":"Language","meta.home.title":"Lumen \xB7 Edge inference and telemetry","meta.home.desc":"Lumen is an edge AI gateway with streaming completions, trace events, telemetry ingest and alert delivery.","meta.docs.title":"Quickstart \xB7 Lumen Docs","meta.docs.desc":"Lumen API quickstart: authentication, chat completions, event streams, telemetry ingest and the push gateway.","meta.status.title":"Status \xB7 Lumen","meta.status.desc":"Live operational status for Lumen chat completions, event streams, telemetry ingest and the push gateway.","meta.about.title":"About \xB7 Lumen","meta.about.desc":"About Lumen Labs, the team behind the edge inference and telemetry platform.","meta.privacy.title":"Privacy \xB7 Lumen","meta.privacy.desc":"How Lumen handles request metadata, content retention and cookies.","meta.404.title":"404 \xB7 Lumen","meta.404.desc":"The requested page was not found.","meta.signin.title":"Sign in \xB7 Lumen","home.pill":"General availability \xB7 v3.4","home.h1":"Edge inference with a gateway you can audit.","home.lead":"Lumen runs model requests, event streams and telemetry on the same global edge network. One API surface, per-request tracing, and no cold starts.","home.cta.primary":"Read the quickstart","home.cta.secondary":"Live status","home.card1.title":"Chat completions","home.card1.body":"Stream tokens over a single long-lived request. <code>POST /api/v1/chat</code>","home.card2.title":"Event streams","home.card2.body":"Server-sent events for agent traces and tool calls. <code>GET /api/v2beta/events</code>","home.card3.title":"Telemetry ingest","home.card3.body":"Batch spans and metrics from any runtime. <code>POST /telemetry/ingest</code>","home.card4.title":"Push gateway","home.card4.body":"Deliver latency and quota alerts to subscribers. <code>GET /push/gateway</code>","home.single.title":"A single request","home.single.lead":"All endpoints take a bearer token. The catalogue is public.","home.single.note":'Browse available models at <a href="/api/v1/models">/api/v1/models</a> or see the <a href="/docs">quickstart</a>.',"docs.h1":"Quickstart","docs.lead":"Everything is served from the edge. Requests are authenticated with a bearer token issued by your workspace administrator.","docs.auth.title":"1. Authentication","docs.auth.body":"Send the key in the <code>Authorization</code> header. Missing or unrecognised keys return <code>401</code> with a JSON error body.","docs.chat.title":"2. Chat completions","docs.chat.body":'Create a completion with <code>POST /api/v1/chat</code>. Set <code>"stream": true</code> to receive incremental deltas.',"docs.events.title":"3. Event streams","docs.events.body":"<code>GET /api/v2beta/events</code> keeps a connection open and emits <code>text/event-stream</code> frames for agent traces and tool invocations. Resume with <code>Last-Event-ID</code>.","docs.telemetry.title":"4. Telemetry ingest","docs.telemetry.body":"Applications push spans to <code>POST /telemetry/ingest</code>. Payloads are newline-delimited JSON and are accepted asynchronously.","docs.push.title":"5. Push gateway","docs.push.body":"<code>GET /push/gateway</code> is a long-poll channel for quota and latency alerts. Subscribe once and keep the connection open.","docs.ref.title":"Reference","docs.th.method":"Method","docs.th.path":"Path","docs.th.auth":"Auth","docs.th.purpose":"Purpose","docs.cat.models":"Model catalogue","docs.cat.chat":"Completions","docs.cat.events":"Trace event stream","docs.cat.telemetry":"Span and metric ingest","docs.cat.push":"Alert subscription","docs.cat.health":"Liveness probe","docs.authval.public":"Public","docs.error.title":"Error format","docs.error.body":'{"error":{"message":"Missing API key.","type":"invalid_request_error","param":null,"code":"missing_api_key"}}',"status.h1":"Status","status.ok":"All systems operational","status.checked":"checked just now","status.th.component":"Component","status.th.uptime":"Uptime (30d)","status.th.state":"State","status.comp.chat":"Chat completions","status.comp.events":"Event streams","status.comp.telemetry":"Telemetry ingest","status.comp.push":"Push gateway","status.comp.edge":"Edge API","status.value.operational":"Operational","status.incidents.title":"Past incidents","status.incidents.body":"No incidents reported in the last 30 days. Scheduled maintenance is announced at least 72 hours in advance.","about.h1":"About Lumen","about.lead":"Lumen Labs builds a small, opinionated edge platform for teams that ship inference and observability together. We run the gateway, the event pipeline and the telemetry collector on the same network so latency, cost and trace data stay in one place.","about.what.title":"What we do","about.what.body":"Our customers are product teams running assistants, agent workflows and background jobs. They care about p95 latency, per-tenant quota and the ability to replay any request when something goes wrong.","about.contact.title":"Contact","about.contact.body":'Support and security questions: <a href="mailto:support@lumenlabs.example">support@lumenlabs.example</a>. We publish incident updates on the <a href="/status">status page</a> and document every endpoint in the <a href="/docs">API reference</a>.',"privacy.h1":"Privacy policy","privacy.updated":"Last updated: 1 May 2026","privacy.data.title":"Data we process","privacy.data.body":"Request metadata (timestamps, status codes, token counts) is retained for 30 days for billing and reliability purposes. Prompt and completion content is never retained unless a workspace administrator explicitly enables request logging.","privacy.cookies.title":"Cookies","privacy.cookies.body":"This site sets no advertising or analytics cookies. Session cookies are only issued inside the console after sign-in.","privacy.third.title":"Third parties","privacy.third.body":"We do not sell data. Infrastructure providers process traffic on our behalf under standard data-processing terms.","privacy.contact.title":"Contact","privacy.contact.body":'Privacy questions can be sent to <a href="mailto:privacy@lumenlabs.example">privacy@lumenlabs.example</a>.',"nf.h1":"Page not found","nf.body":"The page you requested does not exist or has moved. Check the address, or start from one of these:","nf.home":"Home","nf.docs":"Documentation","nf.status":"Status","signin.h1":"Sign in","signin.lead":"Use your workspace credentials to continue.","signin.id":"Workspace ID","signin.key":"Access key","signin.submit":"Continue","signin.note":"Credentials are verified by the server.","signin.err":"Those credentials don't match our records.","signin.limited":"Too many attempts. Try again later.","signin.net":"Network error. Please try again."},zh:{"nav.docs":"\u6587\u6863","nav.status":"\u72B6\u6001","nav.about":"\u5173\u4E8E","nav.privacy":"\u9690\u79C1","footer.tagline":"\u8FB9\u7F18\u63A8\u7406\u4E0E\u9065\u6D4B","lang.aria":"\u8BED\u8A00","meta.home.title":"Lumen \xB7 \u8FB9\u7F18\u63A8\u7406\u4E0E\u9065\u6D4B","meta.home.desc":"Lumen \u662F\u4E00\u4E2A\u8FB9\u7F18 AI \u7F51\u5173\uFF0C\u63D0\u4F9B\u6D41\u5F0F\u8865\u5168\u3001\u8FFD\u8E2A\u4E8B\u4EF6\u3001\u9065\u6D4B\u4E0A\u62A5\u4E0E\u544A\u8B66\u6295\u9012\u3002","meta.docs.title":"\u5FEB\u901F\u5F00\u59CB \xB7 Lumen \u6587\u6863","meta.docs.desc":"Lumen API \u5FEB\u901F\u5F00\u59CB\uFF1A\u8BA4\u8BC1\u3001\u5BF9\u8BDD\u8865\u5168\u3001\u4E8B\u4EF6\u6D41\u3001\u9065\u6D4B\u4E0A\u62A5\u4E0E\u63A8\u9001\u7F51\u5173\u3002","meta.status.title":"\u72B6\u6001 \xB7 Lumen","meta.status.desc":"Lumen \u5BF9\u8BDD\u8865\u5168\u3001\u4E8B\u4EF6\u6D41\u3001\u9065\u6D4B\u4E0A\u62A5\u4E0E\u63A8\u9001\u7F51\u5173\u7684\u5B9E\u65F6\u8FD0\u884C\u72B6\u6001\u3002","meta.about.title":"\u5173\u4E8E \xB7 Lumen","meta.about.desc":"\u4E86\u89E3 Lumen Labs\u2014\u2014\u8FB9\u7F18\u63A8\u7406\u4E0E\u9065\u6D4B\u5E73\u53F0\u80CC\u540E\u7684\u56E2\u961F\u3002","meta.privacy.title":"\u9690\u79C1 \xB7 Lumen","meta.privacy.desc":"Lumen \u5982\u4F55\u5904\u7406\u8BF7\u6C42\u5143\u6570\u636E\u3001\u5185\u5BB9\u7559\u5B58\u4E0E Cookie\u3002","meta.404.title":"404 \xB7 Lumen","meta.404.desc":"\u672A\u627E\u5230\u6240\u8BF7\u6C42\u7684\u9875\u9762\u3002","meta.signin.title":"\u767B\u5F55 \xB7 Lumen","home.pill":"\u6B63\u5F0F\u53EF\u7528 \xB7 v3.4","home.h1":"\u8FB9\u7F18\u63A8\u7406\uFF0C\u7F51\u5173\u53EF\u5BA1\u8BA1\u3002","home.lead":"Lumen \u5728\u540C\u4E00\u5F20\u5168\u7403\u8FB9\u7F18\u7F51\u7EDC\u4E0A\u5904\u7406\u6A21\u578B\u8BF7\u6C42\u3001\u4E8B\u4EF6\u6D41\u4E0E\u9065\u6D4B\u3002\u5355\u4E00 API \u63A5\u53E3\u3001\u9010\u8BF7\u6C42\u8FFD\u8E2A\uFF0C\u6CA1\u6709\u51B7\u542F\u52A8\u3002","home.cta.primary":"\u9605\u8BFB\u5FEB\u901F\u5F00\u59CB","home.cta.secondary":"\u67E5\u770B\u5B9E\u65F6\u72B6\u6001","home.card1.title":"\u5BF9\u8BDD\u8865\u5168","home.card1.body":"\u5728\u4E00\u6B21\u957F\u8FDE\u63A5\u8BF7\u6C42\u4E2D\u6D41\u5F0F\u8F93\u51FA token\u3002<code>POST /api/v1/chat</code>","home.card2.title":"\u4E8B\u4EF6\u6D41","home.card2.body":"\u4E3A\u667A\u80FD\u4F53\u8FFD\u8E2A\u4E0E\u5DE5\u5177\u8C03\u7528\u63D0\u4F9B\u7684\u670D\u52A1\u7AEF\u4E8B\u4EF6\u6D41\u3002<code>GET /api/v2beta/events</code>","home.card3.title":"\u9065\u6D4B\u4E0A\u62A5","home.card3.body":"\u4ECE\u4EFB\u610F\u8FD0\u884C\u65F6\u6279\u91CF\u4E0A\u62A5 span \u4E0E\u6307\u6807\u3002<code>POST /telemetry/ingest</code>","home.card4.title":"\u63A8\u9001\u7F51\u5173","home.card4.body":"\u5411\u8BA2\u9605\u8005\u6295\u9012\u5EF6\u8FDF\u4E0E\u914D\u989D\u544A\u8B66\u3002<code>GET /push/gateway</code>","home.single.title":"\u4E00\u6B21\u8BF7\u6C42","home.single.lead":"\u6240\u6709\u7AEF\u70B9\u90FD\u4F7F\u7528 bearer \u4EE4\u724C\uFF0C\u6A21\u578B\u76EE\u5F55\u516C\u5F00\u53EF\u67E5\u3002","home.single.note":'\u5728 <a href="/api/v1/models">/api/v1/models</a> \u6D4F\u89C8\u53EF\u7528\u6A21\u578B\uFF0C\u6216\u67E5\u770B<a href="/docs">\u5FEB\u901F\u5F00\u59CB</a>\u3002',"docs.h1":"\u5FEB\u901F\u5F00\u59CB","docs.lead":"\u6240\u6709\u670D\u52A1\u90FD\u7531\u8FB9\u7F18\u8282\u70B9\u63D0\u4F9B\u3002\u8BF7\u6C42\u4F7F\u7528\u5DE5\u4F5C\u533A\u7BA1\u7406\u5458\u7B7E\u53D1\u7684 bearer \u4EE4\u724C\u8FDB\u884C\u8BA4\u8BC1\u3002","docs.auth.title":"1. \u8BA4\u8BC1","docs.auth.body":"\u5728 <code>Authorization</code> \u8BF7\u6C42\u5934\u4E2D\u643A\u5E26\u5BC6\u94A5\u3002\u7F3A\u5931\u6216\u65E0\u6CD5\u8BC6\u522B\u7684\u5BC6\u94A5\u4F1A\u8FD4\u56DE <code>401</code>\uFF0C\u5E76\u5E26\u6709 JSON \u9519\u8BEF\u4F53\u3002","docs.chat.title":"2. \u5BF9\u8BDD\u8865\u5168","docs.chat.body":'\u901A\u8FC7 <code>POST /api/v1/chat</code> \u521B\u5EFA\u8865\u5168\u3002\u8BBE\u7F6E <code>"stream": true</code> \u53EF\u83B7\u5F97\u589E\u91CF\u7247\u6BB5\u3002',"docs.events.title":"3. \u4E8B\u4EF6\u6D41","docs.events.body":"<code>GET /api/v2beta/events</code> \u4FDD\u6301\u8FDE\u63A5\u5E38\u5F00\uFF0C\u5E76\u4EE5 <code>text/event-stream</code> \u5E27\u63A8\u9001\u667A\u80FD\u4F53\u8FFD\u8E2A\u4E0E\u5DE5\u5177\u8C03\u7528\u4E8B\u4EF6\u3002\u53EF\u901A\u8FC7 <code>Last-Event-ID</code> \u7EED\u4F20\u3002","docs.telemetry.title":"4. \u9065\u6D4B\u4E0A\u62A5","docs.telemetry.body":"\u5E94\u7528\u628A span \u63A8\u9001\u5230 <code>POST /telemetry/ingest</code>\u3002\u8F7D\u8377\u4E3A\u6309\u884C\u5206\u9694\u7684 JSON\uFF0C\u5F02\u6B65\u63A5\u6536\u3002","docs.push.title":"5. \u63A8\u9001\u7F51\u5173","docs.push.body":"<code>GET /push/gateway</code> \u662F\u7528\u4E8E\u914D\u989D\u4E0E\u5EF6\u8FDF\u544A\u8B66\u7684\u957F\u8F6E\u8BE2\u901A\u9053\u3002\u8BA2\u9605\u4E00\u6B21\u5E76\u4FDD\u6301\u8FDE\u63A5\u5E38\u5F00\u5373\u53EF\u3002","docs.ref.title":"\u63A5\u53E3\u53C2\u8003","docs.th.method":"\u65B9\u6CD5","docs.th.path":"\u8DEF\u5F84","docs.th.auth":"\u8BA4\u8BC1","docs.th.purpose":"\u7528\u9014","docs.cat.models":"\u6A21\u578B\u76EE\u5F55","docs.cat.chat":"\u5BF9\u8BDD\u8865\u5168","docs.cat.events":"\u8FFD\u8E2A\u4E8B\u4EF6\u6D41","docs.cat.telemetry":"span \u4E0E\u6307\u6807\u4E0A\u62A5","docs.cat.push":"\u544A\u8B66\u8BA2\u9605","docs.cat.health":"\u5B58\u6D3B\u63A2\u9488","docs.authval.public":"\u516C\u5F00","docs.error.title":"\u9519\u8BEF\u683C\u5F0F","docs.error.body":'{"error":{"message":"\u7F3A\u5C11 API \u5BC6\u94A5\u3002","type":"invalid_request_error","param":null,"code":"missing_api_key"}}',"status.h1":"\u72B6\u6001","status.ok":"\u6240\u6709\u7CFB\u7EDF\u8FD0\u884C\u6B63\u5E38","status.checked":"\u521A\u521A\u68C0\u67E5","status.th.component":"\u7EC4\u4EF6","status.th.uptime":"\u53EF\u7528\u7387\uFF0830 \u5929\uFF09","status.th.state":"\u72B6\u6001","status.comp.chat":"\u5BF9\u8BDD\u8865\u5168","status.comp.events":"\u4E8B\u4EF6\u6D41","status.comp.telemetry":"\u9065\u6D4B\u4E0A\u62A5","status.comp.push":"\u63A8\u9001\u7F51\u5173","status.comp.edge":"\u8FB9\u7F18 API","status.value.operational":"\u8FD0\u884C\u4E2D","status.incidents.title":"\u5386\u53F2\u4E8B\u4EF6","status.incidents.body":"\u6700\u8FD1 30 \u5929\u672A\u62A5\u544A\u4EFB\u4F55\u4E8B\u4EF6\u3002\u8BA1\u5212\u7EF4\u62A4\u81F3\u5C11\u63D0\u524D 72 \u5C0F\u65F6\u516C\u544A\u3002","about.h1":"\u5173\u4E8E Lumen","about.lead":"Lumen Labs \u4E3A\u540C\u65F6\u4EA4\u4ED8\u63A8\u7406\u4E0E\u53EF\u89C2\u6D4B\u6027\u7684\u56E2\u961F\u6253\u9020\u4E00\u4E2A\u514B\u5236\u800C\u4E13\u6CE8\u7684\u8FB9\u7F18\u5E73\u53F0\u3002\u6211\u4EEC\u628A\u7F51\u5173\u3001\u4E8B\u4EF6\u7BA1\u9053\u548C\u9065\u6D4B\u6536\u96C6\u5668\u653E\u5728\u540C\u4E00\u5F20\u7F51\u7EDC\u4E0A\uFF0C\u8BA9\u5EF6\u8FDF\u3001\u6210\u672C\u4E0E\u8FFD\u8E2A\u6570\u636E\u96C6\u4E2D\u5728\u4E00\u5904\u3002","about.what.title":"\u6211\u4EEC\u505A\u4EC0\u4E48","about.what.body":"\u6211\u4EEC\u7684\u5BA2\u6237\u662F\u8FD0\u884C\u52A9\u624B\u3001\u667A\u80FD\u4F53\u5DE5\u4F5C\u6D41\u548C\u540E\u53F0\u4EFB\u52A1\u7684\u4EA7\u54C1\u56E2\u961F\u3002\u4ED6\u4EEC\u5173\u5FC3 p95 \u5EF6\u8FDF\u3001\u6309\u79DF\u6237\u914D\u989D\uFF0C\u4EE5\u53CA\u51FA\u95EE\u9898\u65F6\u80FD\u591F\u91CD\u653E\u4EFB\u610F\u8BF7\u6C42\u3002","about.contact.title":"\u8054\u7CFB","about.contact.body":'\u652F\u6301\u4E0E\u5B89\u5168\u95EE\u9898\uFF1A<a href="mailto:support@lumenlabs.example">support@lumenlabs.example</a>\u3002\u6211\u4EEC\u4F1A\u5728<a href="/status">\u72B6\u6001\u9875</a>\u53D1\u5E03\u4E8B\u4EF6\u66F4\u65B0\uFF0C\u5E76\u5728<a href="/docs">API \u53C2\u8003</a>\u4E2D\u8BB0\u5F55\u6BCF\u4E2A\u7AEF\u70B9\u3002',"privacy.h1":"\u9690\u79C1\u653F\u7B56","privacy.updated":"\u6700\u540E\u66F4\u65B0\uFF1A2026 \u5E74 5 \u6708 1 \u65E5","privacy.data.title":"\u6211\u4EEC\u5904\u7406\u7684\u6570\u636E","privacy.data.body":"\u8BF7\u6C42\u5143\u6570\u636E\uFF08\u65F6\u95F4\u6233\u3001\u72B6\u6001\u7801\u3001token \u6570\u91CF\uFF09\u4FDD\u7559 30 \u5929\uFF0C\u7528\u4E8E\u8BA1\u8D39\u4E0E\u53EF\u9760\u6027\u5206\u6790\u3002\u9664\u975E\u5DE5\u4F5C\u533A\u7BA1\u7406\u5458\u660E\u786E\u5F00\u542F\u8BF7\u6C42\u65E5\u5FD7\uFF0C\u63D0\u793A\u8BCD\u4E0E\u8865\u5168\u5185\u5BB9\u4E00\u5F8B\u4E0D\u4FDD\u7559\u3002","privacy.cookies.title":"Cookie","privacy.cookies.body":"\u672C\u7AD9\u4E0D\u8BBE\u7F6E\u4EFB\u4F55\u5E7F\u544A\u6216\u5206\u6790 Cookie\u3002\u4F1A\u8BDD Cookie \u4EC5\u5728\u767B\u5F55\u540E\u7531\u63A7\u5236\u53F0\u4E0B\u53D1\u3002","privacy.third.title":"\u7B2C\u4E09\u65B9","privacy.third.body":"\u6211\u4EEC\u4E0D\u51FA\u552E\u6570\u636E\u3002\u57FA\u7840\u8BBE\u65BD\u670D\u52A1\u5546\u6309\u6807\u51C6\u6570\u636E\u5904\u7406\u6761\u6B3E\u4EE3\u8868\u6211\u4EEC\u5904\u7406\u6D41\u91CF\u3002","privacy.contact.title":"\u8054\u7CFB","privacy.contact.body":'\u9690\u79C1\u95EE\u9898\u53EF\u53D1\u9001\u81F3 <a href="mailto:privacy@lumenlabs.example">privacy@lumenlabs.example</a>\u3002',"nf.h1":"\u9875\u9762\u672A\u627E\u5230","nf.body":"\u4F60\u8BF7\u6C42\u7684\u9875\u9762\u4E0D\u5B58\u5728\u6216\u5DF2\u79FB\u52A8\u3002\u8BF7\u68C0\u67E5\u5730\u5740\uFF0C\u6216\u4ECE\u4EE5\u4E0B\u5165\u53E3\u5F00\u59CB\uFF1A","nf.home":"\u9996\u9875","nf.docs":"\u6587\u6863","nf.status":"\u72B6\u6001","signin.h1":"\u767B\u5F55","signin.lead":"\u4F7F\u7528\u5DE5\u4F5C\u533A\u51ED\u8BC1\u7EE7\u7EED\u3002","signin.id":"\u5DE5\u4F5C\u533A ID","signin.key":"\u8BBF\u95EE\u5BC6\u94A5","signin.submit":"\u7EE7\u7EED","signin.note":"\u51ED\u8BC1\u7531\u670D\u52A1\u7AEF\u6821\u9A8C\u3002","signin.err":"\u51ED\u8BC1\u4E0E\u8BB0\u5F55\u4E0D\u5339\u914D\u3002","signin.limited":"\u5C1D\u8BD5\u6B21\u6570\u8FC7\u591A\uFF0C\u8BF7\u7A0D\u540E\u518D\u8BD5\u3002","signin.net":"\u7F51\u7EDC\u5F02\u5E38\uFF0C\u8BF7\u91CD\u8BD5\u3002"},ja:{"nav.docs":"\u30C9\u30AD\u30E5\u30E1\u30F3\u30C8","nav.status":"\u30B9\u30C6\u30FC\u30BF\u30B9","nav.about":"\u6982\u8981","nav.privacy":"\u30D7\u30E9\u30A4\u30D0\u30B7\u30FC","footer.tagline":"\u30A8\u30C3\u30B8\u63A8\u8AD6\u3068\u30C6\u30EC\u30E1\u30C8\u30EA\u30FC","lang.aria":"\u8A00\u8A9E","meta.home.title":"Lumen \xB7 \u30A8\u30C3\u30B8\u63A8\u8AD6\u3068\u30C6\u30EC\u30E1\u30C8\u30EA\u30FC","meta.home.desc":"Lumen \u306F\u3001\u30B9\u30C8\u30EA\u30FC\u30DF\u30F3\u30B0\u88DC\u5B8C\u3001\u30C8\u30EC\u30FC\u30B9\u30A4\u30D9\u30F3\u30C8\u3001\u30C6\u30EC\u30E1\u30C8\u30EA\u30FC\u53D6\u308A\u8FBC\u307F\u3001\u30A2\u30E9\u30FC\u30C8\u914D\u4FE1\u3092\u5099\u3048\u305F\u30A8\u30C3\u30B8 AI \u30B2\u30FC\u30C8\u30A6\u30A7\u30A4\u3067\u3059\u3002","meta.docs.title":"\u30AF\u30A4\u30C3\u30AF\u30B9\u30BF\u30FC\u30C8 \xB7 Lumen \u30C9\u30AD\u30E5\u30E1\u30F3\u30C8","meta.docs.desc":"Lumen API \u30AF\u30A4\u30C3\u30AF\u30B9\u30BF\u30FC\u30C8\uFF1A\u8A8D\u8A3C\u3001\u30C1\u30E3\u30C3\u30C8\u88DC\u5B8C\u3001\u30A4\u30D9\u30F3\u30C8\u30B9\u30C8\u30EA\u30FC\u30E0\u3001\u30C6\u30EC\u30E1\u30C8\u30EA\u30FC\u53D6\u308A\u8FBC\u307F\u3001\u30D7\u30C3\u30B7\u30E5\u30B2\u30FC\u30C8\u30A6\u30A7\u30A4\u3002","meta.status.title":"\u30B9\u30C6\u30FC\u30BF\u30B9 \xB7 Lumen","meta.status.desc":"Lumen \u306E\u30C1\u30E3\u30C3\u30C8\u88DC\u5B8C\u3001\u30A4\u30D9\u30F3\u30C8\u30B9\u30C8\u30EA\u30FC\u30E0\u3001\u30C6\u30EC\u30E1\u30C8\u30EA\u30FC\u53D6\u308A\u8FBC\u307F\u3001\u30D7\u30C3\u30B7\u30E5\u30B2\u30FC\u30C8\u30A6\u30A7\u30A4\u306E\u7A3C\u50CD\u72B6\u6CC1\u3002","meta.about.title":"\u6982\u8981 \xB7 Lumen","meta.about.desc":"\u30A8\u30C3\u30B8\u63A8\u8AD6\u3068\u30C6\u30EC\u30E1\u30C8\u30EA\u30FC\u30D7\u30E9\u30C3\u30C8\u30D5\u30A9\u30FC\u30E0\u3092\u63D0\u4F9B\u3059\u308B Lumen Labs \u306B\u3064\u3044\u3066\u3002","meta.privacy.title":"\u30D7\u30E9\u30A4\u30D0\u30B7\u30FC \xB7 Lumen","meta.privacy.desc":"Lumen \u304C\u30EA\u30AF\u30A8\u30B9\u30C8\u30E1\u30BF\u30C7\u30FC\u30BF\u3001\u30B3\u30F3\u30C6\u30F3\u30C4\u306E\u4FDD\u6301\u3001Cookie \u3092\u3069\u306E\u3088\u3046\u306B\u6271\u3046\u304B\u3002","meta.404.title":"404 \xB7 Lumen","meta.404.desc":"\u6307\u5B9A\u3055\u308C\u305F\u30DA\u30FC\u30B8\u306F\u898B\u3064\u304B\u308A\u307E\u305B\u3093\u3067\u3057\u305F\u3002","meta.signin.title":"\u30B5\u30A4\u30F3\u30A4\u30F3 \xB7 Lumen","home.pill":"\u4E00\u822C\u63D0\u4F9B\u4E2D \xB7 v3.4","home.h1":"\u76E3\u67FB\u3067\u304D\u308B\u30B2\u30FC\u30C8\u30A6\u30A7\u30A4\u3067\u3001\u30A8\u30C3\u30B8\u63A8\u8AD6\u3092\u3002","home.lead":"Lumen \u306F\u30E2\u30C7\u30EB\u30EA\u30AF\u30A8\u30B9\u30C8\u3001\u30A4\u30D9\u30F3\u30C8\u30B9\u30C8\u30EA\u30FC\u30E0\u3001\u30C6\u30EC\u30E1\u30C8\u30EA\u30FC\u3092\u540C\u3058\u30B0\u30ED\u30FC\u30D0\u30EB\u30A8\u30C3\u30B8\u30CD\u30C3\u30C8\u30EF\u30FC\u30AF\u4E0A\u3067\u51E6\u7406\u3057\u307E\u3059\u3002\u5358\u4E00\u306E API \u9762\u3001\u30EA\u30AF\u30A8\u30B9\u30C8\u5358\u4F4D\u306E\u30C8\u30EC\u30FC\u30B9\u3001\u30B3\u30FC\u30EB\u30C9\u30B9\u30BF\u30FC\u30C8\u306A\u3057\u3002","home.cta.primary":"\u30AF\u30A4\u30C3\u30AF\u30B9\u30BF\u30FC\u30C8\u3092\u8AAD\u3080","home.cta.secondary":"\u7A3C\u50CD\u72B6\u6CC1\u3092\u898B\u308B","home.card1.title":"\u30C1\u30E3\u30C3\u30C8\u88DC\u5B8C","home.card1.body":"1 \u672C\u306E\u9577\u6642\u9593\u63A5\u7D9A\u3067\u30C8\u30FC\u30AF\u30F3\u3092\u30B9\u30C8\u30EA\u30FC\u30DF\u30F3\u30B0\u3002<code>POST /api/v1/chat</code>","home.card2.title":"\u30A4\u30D9\u30F3\u30C8\u30B9\u30C8\u30EA\u30FC\u30E0","home.card2.body":"\u30A8\u30FC\u30B8\u30A7\u30F3\u30C8\u306E\u30C8\u30EC\u30FC\u30B9\u3068\u30C4\u30FC\u30EB\u547C\u3073\u51FA\u3057\u5411\u3051\u306E\u30B5\u30FC\u30D0\u30FC\u9001\u4FE1\u30A4\u30D9\u30F3\u30C8\u3002<code>GET /api/v2beta/events</code>","home.card3.title":"\u30C6\u30EC\u30E1\u30C8\u30EA\u30FC\u53D6\u308A\u8FBC\u307F","home.card3.body":"\u4EFB\u610F\u306E\u30E9\u30F3\u30BF\u30A4\u30E0\u304B\u3089 span \u3068\u30E1\u30C8\u30EA\u30AF\u30B9\u3092\u4E00\u62EC\u9001\u4FE1\u3002<code>POST /telemetry/ingest</code>","home.card4.title":"\u30D7\u30C3\u30B7\u30E5\u30B2\u30FC\u30C8\u30A6\u30A7\u30A4","home.card4.body":"\u30EC\u30A4\u30C6\u30F3\u30B7\u3068\u30AF\u30A9\u30FC\u30BF\u306E\u30A2\u30E9\u30FC\u30C8\u3092\u8CFC\u8AAD\u8005\u3078\u914D\u4FE1\u3002<code>GET /push/gateway</code>","home.single.title":"1 \u56DE\u306E\u30EA\u30AF\u30A8\u30B9\u30C8","home.single.lead":"\u3059\u3079\u3066\u306E\u30A8\u30F3\u30C9\u30DD\u30A4\u30F3\u30C8\u306F bearer \u30C8\u30FC\u30AF\u30F3\u3092\u8981\u6C42\u3057\u307E\u3059\u3002\u30AB\u30BF\u30ED\u30B0\u306F\u516C\u958B\u3055\u308C\u3066\u3044\u307E\u3059\u3002","home.single.note":'\u5229\u7528\u53EF\u80FD\u306A\u30E2\u30C7\u30EB\u306F <a href="/api/v1/models">/api/v1/models</a> \u3067\u78BA\u8A8D\u3067\u304D\u3001<a href="/docs">\u30AF\u30A4\u30C3\u30AF\u30B9\u30BF\u30FC\u30C8</a>\u3082\u53C2\u7167\u3067\u304D\u307E\u3059\u3002',"docs.h1":"\u30AF\u30A4\u30C3\u30AF\u30B9\u30BF\u30FC\u30C8","docs.lead":"\u3059\u3079\u3066\u306E\u51E6\u7406\u306F\u30A8\u30C3\u30B8\u3067\u884C\u308F\u308C\u307E\u3059\u3002\u30EA\u30AF\u30A8\u30B9\u30C8\u306F\u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9\u7BA1\u7406\u8005\u304C\u767A\u884C\u3059\u308B bearer \u30C8\u30FC\u30AF\u30F3\u3067\u8A8D\u8A3C\u3055\u308C\u307E\u3059\u3002","docs.auth.title":"1. \u8A8D\u8A3C","docs.auth.body":"\u30AD\u30FC\u306F <code>Authorization</code> \u30D8\u30C3\u30C0\u30FC\u3067\u9001\u4FE1\u3057\u307E\u3059\u3002\u30AD\u30FC\u304C\u7121\u3044\u3001\u307E\u305F\u306F\u8A8D\u8B58\u3067\u304D\u306A\u3044\u5834\u5408\u306F <code>401</code> \u3068 JSON \u306E\u30A8\u30E9\u30FC\u672C\u6587\u3092\u8FD4\u3057\u307E\u3059\u3002","docs.chat.title":"2. \u30C1\u30E3\u30C3\u30C8\u88DC\u5B8C","docs.chat.body":'<code>POST /api/v1/chat</code> \u3067\u88DC\u5B8C\u3092\u4F5C\u6210\u3057\u307E\u3059\u3002<code>"stream": true</code> \u3092\u8A2D\u5B9A\u3059\u308B\u3068\u5DEE\u5206\u3092\u9010\u6B21\u53D7\u3051\u53D6\u308C\u307E\u3059\u3002',"docs.events.title":"3. \u30A4\u30D9\u30F3\u30C8\u30B9\u30C8\u30EA\u30FC\u30E0","docs.events.body":"<code>GET /api/v2beta/events</code> \u306F\u63A5\u7D9A\u3092\u7DAD\u6301\u3057\u3001\u30A8\u30FC\u30B8\u30A7\u30F3\u30C8\u306E\u30C8\u30EC\u30FC\u30B9\u3068\u30C4\u30FC\u30EB\u547C\u3073\u51FA\u3057\u3092 <code>text/event-stream</code> \u30D5\u30EC\u30FC\u30E0\u3067\u9001\u51FA\u3057\u307E\u3059\u3002<code>Last-Event-ID</code> \u3067\u518D\u958B\u3067\u304D\u307E\u3059\u3002","docs.telemetry.title":"4. \u30C6\u30EC\u30E1\u30C8\u30EA\u30FC\u53D6\u308A\u8FBC\u307F","docs.telemetry.body":"\u30A2\u30D7\u30EA\u30B1\u30FC\u30B7\u30E7\u30F3\u306F span \u3092 <code>POST /telemetry/ingest</code> \u306B\u9001\u4FE1\u3057\u307E\u3059\u3002\u30DA\u30A4\u30ED\u30FC\u30C9\u306F\u6539\u884C\u533A\u5207\u308A\u306E JSON \u3067\u3001\u975E\u540C\u671F\u306B\u53D7\u3051\u4ED8\u3051\u3089\u308C\u307E\u3059\u3002","docs.push.title":"5. \u30D7\u30C3\u30B7\u30E5\u30B2\u30FC\u30C8\u30A6\u30A7\u30A4","docs.push.body":"<code>GET /push/gateway</code> \u306F\u30AF\u30A9\u30FC\u30BF\u3068\u30EC\u30A4\u30C6\u30F3\u30B7\u306E\u30A2\u30E9\u30FC\u30C8\u5411\u3051\u30ED\u30F3\u30B0\u30DD\u30FC\u30EA\u30F3\u30B0\u7D4C\u8DEF\u3067\u3059\u3002\u4E00\u5EA6\u8CFC\u8AAD\u3057\u3001\u63A5\u7D9A\u3092\u7DAD\u6301\u3057\u3066\u304F\u3060\u3055\u3044\u3002","docs.ref.title":"\u30EA\u30D5\u30A1\u30EC\u30F3\u30B9","docs.th.method":"\u30E1\u30BD\u30C3\u30C9","docs.th.path":"\u30D1\u30B9","docs.th.auth":"\u8A8D\u8A3C","docs.th.purpose":"\u7528\u9014","docs.cat.models":"\u30E2\u30C7\u30EB\u30AB\u30BF\u30ED\u30B0","docs.cat.chat":"\u88DC\u5B8C","docs.cat.events":"\u30C8\u30EC\u30FC\u30B9\u30A4\u30D9\u30F3\u30C8","docs.cat.telemetry":"span \u3068\u30E1\u30C8\u30EA\u30AF\u30B9\u306E\u53D6\u308A\u8FBC\u307F","docs.cat.push":"\u30A2\u30E9\u30FC\u30C8\u8CFC\u8AAD","docs.cat.health":"\u7A3C\u50CD\u78BA\u8A8D","docs.authval.public":"\u516C\u958B","docs.error.title":"\u30A8\u30E9\u30FC\u5F62\u5F0F","docs.error.body":'{"error":{"message":"API \u30AD\u30FC\u304C\u3042\u308A\u307E\u305B\u3093\u3002","type":"invalid_request_error","param":null,"code":"missing_api_key"}}',"status.h1":"\u30B9\u30C6\u30FC\u30BF\u30B9","status.ok":"\u3059\u3079\u3066\u306E\u30B7\u30B9\u30C6\u30E0\u304C\u6B63\u5E38\u306B\u7A3C\u50CD\u4E2D","status.checked":"\u305F\u3063\u305F\u4ECA\u78BA\u8A8D","status.th.component":"\u30B3\u30F3\u30DD\u30FC\u30CD\u30F3\u30C8","status.th.uptime":"\u7A3C\u50CD\u7387\uFF0830 \u65E5\uFF09","status.th.state":"\u72B6\u614B","status.comp.chat":"\u30C1\u30E3\u30C3\u30C8\u88DC\u5B8C","status.comp.events":"\u30A4\u30D9\u30F3\u30C8\u30B9\u30C8\u30EA\u30FC\u30E0","status.comp.telemetry":"\u30C6\u30EC\u30E1\u30C8\u30EA\u30FC\u53D6\u308A\u8FBC\u307F","status.comp.push":"\u30D7\u30C3\u30B7\u30E5\u30B2\u30FC\u30C8\u30A6\u30A7\u30A4","status.comp.edge":"\u30A8\u30C3\u30B8 API","status.value.operational":"\u7A3C\u50CD\u4E2D","status.incidents.title":"\u904E\u53BB\u306E\u30A4\u30F3\u30B7\u30C7\u30F3\u30C8","status.incidents.body":"\u76F4\u8FD1 30 \u65E5\u9593\u306B\u5831\u544A\u3055\u308C\u305F\u30A4\u30F3\u30B7\u30C7\u30F3\u30C8\u306F\u3042\u308A\u307E\u305B\u3093\u3002\u8A08\u753B\u30E1\u30F3\u30C6\u30CA\u30F3\u30B9\u306F\u5C11\u306A\u304F\u3068\u3082 72 \u6642\u9593\u524D\u306B\u544A\u77E5\u3057\u307E\u3059\u3002","about.h1":"Lumen \u306B\u3064\u3044\u3066","about.lead":"Lumen Labs \u306F\u3001\u63A8\u8AD6\u3068\u53EF\u89B3\u6E2C\u6027\u3092\u540C\u6642\u306B\u63D0\u4F9B\u3059\u308B\u30C1\u30FC\u30E0\u5411\u3051\u306B\u3001\u5C0F\u3055\u304F\u660E\u78BA\u306A\u65B9\u91DD\u306E\u30A8\u30C3\u30B8\u30D7\u30E9\u30C3\u30C8\u30D5\u30A9\u30FC\u30E0\u3092\u4F5C\u3063\u3066\u3044\u307E\u3059\u3002\u30B2\u30FC\u30C8\u30A6\u30A7\u30A4\u3001\u30A4\u30D9\u30F3\u30C8\u30D1\u30A4\u30D7\u30E9\u30A4\u30F3\u3001\u30C6\u30EC\u30E1\u30C8\u30EA\u30FC\u53CE\u96C6\u3092\u540C\u3058\u30CD\u30C3\u30C8\u30EF\u30FC\u30AF\u4E0A\u3067\u52D5\u304B\u3057\u3001\u30EC\u30A4\u30C6\u30F3\u30B7\u3001\u30B3\u30B9\u30C8\u3001\u30C8\u30EC\u30FC\u30B9\u30C7\u30FC\u30BF\u3092 1 \u304B\u6240\u306B\u96C6\u3081\u307E\u3059\u3002","about.what.title":"\u79C1\u305F\u3061\u306E\u4ED5\u4E8B","about.what.body":"\u9867\u5BA2\u306F\u30A2\u30B7\u30B9\u30BF\u30F3\u30C8\u3001\u30A8\u30FC\u30B8\u30A7\u30F3\u30C8\u30EF\u30FC\u30AF\u30D5\u30ED\u30FC\u3001\u30D0\u30C3\u30AF\u30B0\u30E9\u30A6\u30F3\u30C9\u30B8\u30E7\u30D6\u3092\u904B\u7528\u3059\u308B\u30D7\u30ED\u30C0\u30AF\u30C8\u30C1\u30FC\u30E0\u3067\u3059\u3002p95 \u30EC\u30A4\u30C6\u30F3\u30B7\u3001\u30C6\u30CA\u30F3\u30C8\u5358\u4F4D\u306E\u30AF\u30A9\u30FC\u30BF\u3001\u969C\u5BB3\u6642\u306B\u4EFB\u610F\u306E\u30EA\u30AF\u30A8\u30B9\u30C8\u3092\u518D\u751F\u3067\u304D\u308B\u3053\u3068\u3092\u91CD\u8996\u3057\u3066\u3044\u307E\u3059\u3002","about.contact.title":"\u304A\u554F\u3044\u5408\u308F\u305B","about.contact.body":'\u30B5\u30DD\u30FC\u30C8\u3068\u30BB\u30AD\u30E5\u30EA\u30C6\u30A3\u306B\u95A2\u3059\u308B\u3054\u8CEA\u554F\uFF1A<a href="mailto:support@lumenlabs.example">support@lumenlabs.example</a>\u3002\u30A4\u30F3\u30B7\u30C7\u30F3\u30C8\u306E\u66F4\u65B0\u306F<a href="/status">\u30B9\u30C6\u30FC\u30BF\u30B9\u30DA\u30FC\u30B8</a>\u3067\u516C\u958B\u3057\u3001\u3059\u3079\u3066\u306E\u30A8\u30F3\u30C9\u30DD\u30A4\u30F3\u30C8\u306F<a href="/docs">API \u30EA\u30D5\u30A1\u30EC\u30F3\u30B9</a>\u306B\u8A18\u8F09\u3057\u3066\u3044\u307E\u3059\u3002',"privacy.h1":"\u30D7\u30E9\u30A4\u30D0\u30B7\u30FC\u30DD\u30EA\u30B7\u30FC","privacy.updated":"\u6700\u7D42\u66F4\u65B0\uFF1A2026 \u5E74 5 \u6708 1 \u65E5","privacy.data.title":"\u51E6\u7406\u3059\u308B\u30C7\u30FC\u30BF","privacy.data.body":"\u30EA\u30AF\u30A8\u30B9\u30C8\u306E\u30E1\u30BF\u30C7\u30FC\u30BF\uFF08\u30BF\u30A4\u30E0\u30B9\u30BF\u30F3\u30D7\u3001\u30B9\u30C6\u30FC\u30BF\u30B9\u30B3\u30FC\u30C9\u3001\u30C8\u30FC\u30AF\u30F3\u6570\uFF09\u306F\u3001\u8AB2\u91D1\u3068\u4FE1\u983C\u6027\u306E\u305F\u3081\u306B 30 \u65E5\u9593\u4FDD\u6301\u3057\u307E\u3059\u3002\u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9\u7BA1\u7406\u8005\u304C\u660E\u793A\u7684\u306B\u30EA\u30AF\u30A8\u30B9\u30C8\u30ED\u30B0\u3092\u6709\u52B9\u306B\u3057\u306A\u3044\u9650\u308A\u3001\u30D7\u30ED\u30F3\u30D7\u30C8\u3068\u88DC\u5B8C\u306E\u5185\u5BB9\u306F\u4FDD\u6301\u3057\u307E\u305B\u3093\u3002","privacy.cookies.title":"Cookie","privacy.cookies.body":"\u672C\u30B5\u30A4\u30C8\u306F\u5E83\u544A\u3084\u5206\u6790\u306E Cookie \u3092\u8A2D\u5B9A\u3057\u307E\u305B\u3093\u3002\u30BB\u30C3\u30B7\u30E7\u30F3 Cookie \u306F\u30B5\u30A4\u30F3\u30A4\u30F3\u5F8C\u306B\u30B3\u30F3\u30BD\u30FC\u30EB\u5185\u3067\u306E\u307F\u767A\u884C\u3055\u308C\u307E\u3059\u3002","privacy.third.title":"\u7B2C\u4E09\u8005","privacy.third.body":"\u5F53\u793E\u306F\u30C7\u30FC\u30BF\u3092\u8CA9\u58F2\u3057\u307E\u305B\u3093\u3002\u30A4\u30F3\u30D5\u30E9\u4E8B\u696D\u8005\u306F\u6A19\u6E96\u7684\u306A\u30C7\u30FC\u30BF\u51E6\u7406\u6761\u9805\u306B\u57FA\u3065\u304D\u3001\u5F53\u793E\u306B\u4EE3\u308F\u3063\u3066\u30C8\u30E9\u30D5\u30A3\u30C3\u30AF\u3092\u51E6\u7406\u3057\u307E\u3059\u3002","privacy.contact.title":"\u304A\u554F\u3044\u5408\u308F\u305B","privacy.contact.body":'\u30D7\u30E9\u30A4\u30D0\u30B7\u30FC\u306B\u95A2\u3059\u308B\u3054\u8CEA\u554F\u306F <a href="mailto:privacy@lumenlabs.example">privacy@lumenlabs.example</a> \u307E\u3067\u3002',"nf.h1":"\u30DA\u30FC\u30B8\u304C\u898B\u3064\u304B\u308A\u307E\u305B\u3093","nf.body":"\u304A\u63A2\u3057\u306E\u30DA\u30FC\u30B8\u306F\u5B58\u5728\u3057\u306A\u3044\u304B\u3001\u79FB\u52D5\u3057\u307E\u3057\u305F\u3002\u30A2\u30C9\u30EC\u30B9\u3092\u78BA\u8A8D\u3059\u308B\u304B\u3001\u4EE5\u4E0B\u306E\u3044\u305A\u308C\u304B\u304B\u3089\u958B\u59CB\u3057\u3066\u304F\u3060\u3055\u3044\uFF1A","nf.home":"\u30DB\u30FC\u30E0","nf.docs":"\u30C9\u30AD\u30E5\u30E1\u30F3\u30C8","nf.status":"\u30B9\u30C6\u30FC\u30BF\u30B9","signin.h1":"\u30B5\u30A4\u30F3\u30A4\u30F3","signin.lead":"\u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9\u306E\u8A8D\u8A3C\u60C5\u5831\u3092\u5165\u529B\u3057\u3066\u304F\u3060\u3055\u3044\u3002","signin.id":"\u30EF\u30FC\u30AF\u30B9\u30DA\u30FC\u30B9 ID","signin.key":"\u30A2\u30AF\u30BB\u30B9\u30AD\u30FC","signin.submit":"\u7D9A\u884C","signin.note":"\u8A8D\u8A3C\u60C5\u5831\u306F\u30B5\u30FC\u30D0\u30FC\u3067\u691C\u8A3C\u3055\u308C\u307E\u3059\u3002","signin.err":"\u8A8D\u8A3C\u60C5\u5831\u304C\u8A18\u9332\u3068\u4E00\u81F4\u3057\u307E\u305B\u3093\u3002","signin.limited":"\u8A66\u884C\u56DE\u6570\u304C\u591A\u3059\u304E\u307E\u3059\u3002\u3057\u3070\u3089\u304F\u3057\u3066\u304B\u3089\u518D\u8A66\u884C\u3057\u3066\u304F\u3060\u3055\u3044\u3002","signin.net":"\u30CD\u30C3\u30C8\u30EF\u30FC\u30AF\u30A8\u30E9\u30FC\u3067\u3059\u3002\u3082\u3046\u4E00\u5EA6\u304A\u8A66\u3057\u304F\u3060\u3055\u3044\u3002"},ru:{"nav.docs":"\u0414\u043E\u043A\u0443\u043C\u0435\u043D\u0442\u044B","nav.status":"\u0421\u0442\u0430\u0442\u0443\u0441","nav.about":"\u041E \u043D\u0430\u0441","nav.privacy":"\u041A\u043E\u043D\u0444\u0438\u0434\u0435\u043D\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0441\u0442\u044C","footer.tagline":"\u0418\u043D\u0444\u0435\u0440\u0435\u043D\u0441 \u0438 \u0442\u0435\u043B\u0435\u043C\u0435\u0442\u0440\u0438\u044F \u043D\u0430 \u043F\u0435\u0440\u0438\u0444\u0435\u0440\u0438\u0438","lang.aria":"\u042F\u0437\u044B\u043A","meta.home.title":"Lumen \xB7 \u0418\u043D\u0444\u0435\u0440\u0435\u043D\u0441 \u0438 \u0442\u0435\u043B\u0435\u043C\u0435\u0442\u0440\u0438\u044F \u043D\u0430 \u043F\u0435\u0440\u0438\u0444\u0435\u0440\u0438\u0438","meta.home.desc":"Lumen \u2014 \u0448\u043B\u044E\u0437 \u0418\u0418 \u043D\u0430 \u043F\u0435\u0440\u0438\u0444\u0435\u0440\u0438\u0438 \u0441 \u043F\u043E\u0442\u043E\u043A\u043E\u0432\u044B\u043C\u0438 \u043E\u0442\u0432\u0435\u0442\u0430\u043C\u0438, \u0441\u043E\u0431\u044B\u0442\u0438\u044F\u043C\u0438 \u0442\u0440\u0430\u0441\u0441\u0438\u0440\u043E\u0432\u043A\u0438, \u043F\u0440\u0438\u0451\u043C\u043E\u043C \u0442\u0435\u043B\u0435\u043C\u0435\u0442\u0440\u0438\u0438 \u0438 \u0434\u043E\u0441\u0442\u0430\u0432\u043A\u043E\u0439 \u043E\u043F\u043E\u0432\u0435\u0449\u0435\u043D\u0438\u0439.","meta.docs.title":"\u0411\u044B\u0441\u0442\u0440\u044B\u0439 \u0441\u0442\u0430\u0440\u0442 \xB7 \u0414\u043E\u043A\u0443\u043C\u0435\u043D\u0442\u0430\u0446\u0438\u044F Lumen","meta.docs.desc":"\u0411\u044B\u0441\u0442\u0440\u044B\u0439 \u0441\u0442\u0430\u0440\u0442 Lumen API: \u0430\u0443\u0442\u0435\u043D\u0442\u0438\u0444\u0438\u043A\u0430\u0446\u0438\u044F, \u0447\u0430\u0442-\u043A\u043E\u043C\u043F\u043B\u0438\u0448\u0435\u043D\u044B, \u043F\u043E\u0442\u043E\u043A\u0438 \u0441\u043E\u0431\u044B\u0442\u0438\u0439, \u043F\u0440\u0438\u0451\u043C \u0442\u0435\u043B\u0435\u043C\u0435\u0442\u0440\u0438\u0438 \u0438 \u0448\u043B\u044E\u0437 \u0434\u043E\u0441\u0442\u0430\u0432\u043A\u0438.","meta.status.title":"\u0421\u0442\u0430\u0442\u0443\u0441 \xB7 Lumen","meta.status.desc":"\u0422\u0435\u043A\u0443\u0449\u0438\u0439 \u0441\u0442\u0430\u0442\u0443\u0441 \u0447\u0430\u0442-\u043A\u043E\u043C\u043F\u043B\u0438\u0448\u0435\u043D\u043E\u0432, \u043F\u043E\u0442\u043E\u043A\u043E\u0432 \u0441\u043E\u0431\u044B\u0442\u0438\u0439, \u043F\u0440\u0438\u0451\u043C\u0430 \u0442\u0435\u043B\u0435\u043C\u0435\u0442\u0440\u0438\u0438 \u0438 \u0448\u043B\u044E\u0437\u0430 \u0434\u043E\u0441\u0442\u0430\u0432\u043A\u0438 Lumen.","meta.about.title":"\u041E \u043D\u0430\u0441 \xB7 Lumen","meta.about.desc":"\u041E Lumen Labs \u2014 \u043A\u043E\u043C\u0430\u043D\u0434\u0435, \u0441\u043E\u0437\u0434\u0430\u044E\u0449\u0435\u0439 \u043F\u043B\u0430\u0442\u0444\u043E\u0440\u043C\u0443 \u043F\u0435\u0440\u0438\u0444\u0435\u0440\u0438\u0439\u043D\u043E\u0433\u043E \u0438\u043D\u0444\u0435\u0440\u0435\u043D\u0441\u0430 \u0438 \u0442\u0435\u043B\u0435\u043C\u0435\u0442\u0440\u0438\u0438.","meta.privacy.title":"\u041A\u043E\u043D\u0444\u0438\u0434\u0435\u043D\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0441\u0442\u044C \xB7 Lumen","meta.privacy.desc":"\u041A\u0430\u043A Lumen \u043E\u0431\u0440\u0430\u0431\u0430\u0442\u044B\u0432\u0430\u0435\u0442 \u043C\u0435\u0442\u0430\u0434\u0430\u043D\u043D\u044B\u0435 \u0437\u0430\u043F\u0440\u043E\u0441\u043E\u0432, \u0445\u0440\u0430\u043D\u0435\u043D\u0438\u0435 \u043A\u043E\u043D\u0442\u0435\u043D\u0442\u0430 \u0438 \u0444\u0430\u0439\u043B\u044B cookie.","meta.404.title":"404 \xB7 Lumen","meta.404.desc":"\u0417\u0430\u043F\u0440\u043E\u0448\u0435\u043D\u043D\u0430\u044F \u0441\u0442\u0440\u0430\u043D\u0438\u0446\u0430 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u0430.","meta.signin.title":"\u0412\u0445\u043E\u0434 \xB7 Lumen","home.pill":"\u041E\u0431\u0449\u0435\u0434\u043E\u0441\u0442\u0443\u043F\u043D\u043E \xB7 v3.4","home.h1":"\u041F\u0435\u0440\u0438\u0444\u0435\u0440\u0438\u0439\u043D\u044B\u0439 \u0438\u043D\u0444\u0435\u0440\u0435\u043D\u0441 \u0441\u043E \u0448\u043B\u044E\u0437\u043E\u043C, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u043C\u043E\u0436\u043D\u043E \u043F\u0440\u043E\u0432\u0435\u0440\u044F\u0442\u044C.","home.lead":"Lumen \u043E\u0431\u0440\u0430\u0431\u0430\u0442\u044B\u0432\u0430\u0435\u0442 \u0437\u0430\u043F\u0440\u043E\u0441\u044B \u043A \u043C\u043E\u0434\u0435\u043B\u044F\u043C, \u043F\u043E\u0442\u043E\u043A\u0438 \u0441\u043E\u0431\u044B\u0442\u0438\u0439 \u0438 \u0442\u0435\u043B\u0435\u043C\u0435\u0442\u0440\u0438\u044E \u0432 \u043E\u0434\u043D\u043E\u0439 \u0433\u043B\u043E\u0431\u0430\u043B\u044C\u043D\u043E\u0439 \u043F\u0435\u0440\u0438\u0444\u0435\u0440\u0438\u0439\u043D\u043E\u0439 \u0441\u0435\u0442\u0438. \u0415\u0434\u0438\u043D\u044B\u0439 API, \u0442\u0440\u0430\u0441\u0441\u0438\u0440\u043E\u0432\u043A\u0430 \u043A\u0430\u0436\u0434\u043E\u0433\u043E \u0437\u0430\u043F\u0440\u043E\u0441\u0430 \u0438 \u043E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0438\u0435 \u0445\u043E\u043B\u043E\u0434\u043D\u044B\u0445 \u0441\u0442\u0430\u0440\u0442\u043E\u0432.","home.cta.primary":"\u0427\u0438\u0442\u0430\u0442\u044C \u0431\u044B\u0441\u0442\u0440\u044B\u0439 \u0441\u0442\u0430\u0440\u0442","home.cta.secondary":"\u0422\u0435\u043A\u0443\u0449\u0438\u0439 \u0441\u0442\u0430\u0442\u0443\u0441","home.card1.title":"\u0427\u0430\u0442-\u043A\u043E\u043C\u043F\u043B\u0438\u0448\u0435\u043D\u044B","home.card1.body":"\u041F\u043E\u0442\u043E\u043A\u043E\u0432\u0430\u044F \u0432\u044B\u0434\u0430\u0447\u0430 \u0442\u043E\u043A\u0435\u043D\u043E\u0432 \u0432 \u043E\u0434\u043D\u043E\u043C \u0434\u043B\u0438\u0442\u0435\u043B\u044C\u043D\u043E\u043C \u0437\u0430\u043F\u0440\u043E\u0441\u0435. <code>POST /api/v1/chat</code>","home.card2.title":"\u041F\u043E\u0442\u043E\u043A\u0438 \u0441\u043E\u0431\u044B\u0442\u0438\u0439","home.card2.body":"\u0421\u0435\u0440\u0432\u0435\u0440\u043D\u044B\u0435 \u0441\u043E\u0431\u044B\u0442\u0438\u044F \u0434\u043B\u044F \u0442\u0440\u0430\u0441\u0441\u0438\u0440\u043E\u0432\u043A\u0438 \u0430\u0433\u0435\u043D\u0442\u043E\u0432 \u0438 \u0432\u044B\u0437\u043E\u0432\u043E\u0432 \u0438\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\u043E\u0432. <code>GET /api/v2beta/events</code>","home.card3.title":"\u041F\u0440\u0438\u0451\u043C \u0442\u0435\u043B\u0435\u043C\u0435\u0442\u0440\u0438\u0438","home.card3.body":"\u041F\u0430\u043A\u0435\u0442\u043D\u0430\u044F \u043E\u0442\u043F\u0440\u0430\u0432\u043A\u0430 \u0441\u043F\u0430\u043D\u043E\u0432 \u0438 \u043C\u0435\u0442\u0440\u0438\u043A \u0438\u0437 \u043B\u044E\u0431\u043E\u0439 \u0441\u0440\u0435\u0434\u044B. <code>POST /telemetry/ingest</code>","home.card4.title":"\u0428\u043B\u044E\u0437 \u0434\u043E\u0441\u0442\u0430\u0432\u043A\u0438","home.card4.body":"\u0414\u043E\u0441\u0442\u0430\u0432\u043A\u0430 \u043E\u043F\u043E\u0432\u0435\u0449\u0435\u043D\u0438\u0439 \u043E \u0437\u0430\u0434\u0435\u0440\u0436\u043A\u0430\u0445 \u0438 \u043A\u0432\u043E\u0442\u0430\u0445 \u043F\u043E\u0434\u043F\u0438\u0441\u0447\u0438\u043A\u0430\u043C. <code>GET /push/gateway</code>","home.single.title":"\u041E\u0434\u0438\u043D \u0437\u0430\u043F\u0440\u043E\u0441","home.single.lead":"\u0412\u0441\u0435 \u044D\u043D\u0434\u043F\u043E\u0438\u043D\u0442\u044B \u043F\u0440\u0438\u043D\u0438\u043C\u0430\u044E\u0442 bearer-\u0442\u043E\u043A\u0435\u043D. \u041A\u0430\u0442\u0430\u043B\u043E\u0433 \u043E\u0442\u043A\u0440\u044B\u0442.","home.single.note":'\u0414\u043E\u0441\u0442\u0443\u043F\u043D\u044B\u0435 \u043C\u043E\u0434\u0435\u043B\u0438 \u2014 \u043D\u0430 <a href="/api/v1/models">/api/v1/models</a>, \u0442\u0430\u043A\u0436\u0435 \u0441\u043C. <a href="/docs">\u0431\u044B\u0441\u0442\u0440\u044B\u0439 \u0441\u0442\u0430\u0440\u0442</a>.',"docs.h1":"\u0411\u044B\u0441\u0442\u0440\u044B\u0439 \u0441\u0442\u0430\u0440\u0442","docs.lead":"\u0412\u0441\u0451 \u043E\u0431\u0441\u043B\u0443\u0436\u0438\u0432\u0430\u0435\u0442\u0441\u044F \u043D\u0430 \u043F\u0435\u0440\u0438\u0444\u0435\u0440\u0438\u0438. \u0417\u0430\u043F\u0440\u043E\u0441\u044B \u0430\u0443\u0442\u0435\u043D\u0442\u0438\u0444\u0438\u0446\u0438\u0440\u0443\u044E\u0442\u0441\u044F bearer-\u0442\u043E\u043A\u0435\u043D\u043E\u043C, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u0432\u044B\u0434\u0430\u0451\u0442 \u0430\u0434\u043C\u0438\u043D\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440 \u0440\u0430\u0431\u043E\u0447\u0435\u0433\u043E \u043F\u0440\u043E\u0441\u0442\u0440\u0430\u043D\u0441\u0442\u0432\u0430.","docs.auth.title":"1. \u0410\u0443\u0442\u0435\u043D\u0442\u0438\u0444\u0438\u043A\u0430\u0446\u0438\u044F","docs.auth.body":"\u041F\u0435\u0440\u0435\u0434\u0430\u0439\u0442\u0435 \u043A\u043B\u044E\u0447 \u0432 \u0437\u0430\u0433\u043E\u043B\u043E\u0432\u043A\u0435 <code>Authorization</code>. \u041E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u044E\u0449\u0438\u0439 \u0438\u043B\u0438 \u043D\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043D\u044B\u0439 \u043A\u043B\u044E\u0447 \u0432\u043E\u0437\u0432\u0440\u0430\u0449\u0430\u0435\u0442 <code>401</code> \u0441 \u0442\u0435\u043B\u043E\u043C \u043E\u0448\u0438\u0431\u043A\u0438 \u0432 JSON.","docs.chat.title":"2. \u0427\u0430\u0442-\u043A\u043E\u043C\u043F\u043B\u0438\u0448\u0435\u043D\u044B","docs.chat.body":'\u0421\u043E\u0437\u0434\u0430\u0439\u0442\u0435 \u043A\u043E\u043C\u043F\u043B\u0438\u0448\u0435\u043D \u0447\u0435\u0440\u0435\u0437 <code>POST /api/v1/chat</code>. \u0423\u0441\u0442\u0430\u043D\u043E\u0432\u0438\u0442\u0435 <code>"stream": true</code>, \u0447\u0442\u043E\u0431\u044B \u043F\u043E\u043B\u0443\u0447\u0430\u0442\u044C \u0438\u043D\u043A\u0440\u0435\u043C\u0435\u043D\u0442\u0430\u043B\u044C\u043D\u044B\u0435 \u0434\u0435\u043B\u044C\u0442\u044B.',"docs.events.title":"3. \u041F\u043E\u0442\u043E\u043A\u0438 \u0441\u043E\u0431\u044B\u0442\u0438\u0439","docs.events.body":"<code>GET /api/v2beta/events</code> \u0434\u0435\u0440\u0436\u0438\u0442 \u0441\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0435 \u043E\u0442\u043A\u0440\u044B\u0442\u044B\u043C \u0438 \u043E\u0442\u043F\u0440\u0430\u0432\u043B\u044F\u0435\u0442 \u043A\u0430\u0434\u0440\u044B <code>text/event-stream</code> \u0441 \u0442\u0440\u0430\u0441\u0441\u0438\u0440\u043E\u0432\u043A\u0430\u043C\u0438 \u0430\u0433\u0435\u043D\u0442\u043E\u0432 \u0438 \u0432\u044B\u0437\u043E\u0432\u0430\u043C\u0438 \u0438\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\u043E\u0432. \u041F\u0440\u043E\u0434\u043E\u043B\u0436\u0435\u043D\u0438\u0435 \u2014 \u0447\u0435\u0440\u0435\u0437 <code>Last-Event-ID</code>.","docs.telemetry.title":"4. \u041F\u0440\u0438\u0451\u043C \u0442\u0435\u043B\u0435\u043C\u0435\u0442\u0440\u0438\u0438","docs.telemetry.body":"\u041F\u0440\u0438\u043B\u043E\u0436\u0435\u043D\u0438\u044F \u043E\u0442\u043F\u0440\u0430\u0432\u043B\u044F\u044E\u0442 \u0441\u043F\u0430\u043D\u044B \u0432 <code>POST /telemetry/ingest</code>. \u041F\u043E\u043B\u0435\u0437\u043D\u0430\u044F \u043D\u0430\u0433\u0440\u0443\u0437\u043A\u0430 \u2014 JSON \u0441 \u0440\u0430\u0437\u0434\u0435\u043B\u0435\u043D\u0438\u0435\u043C \u0441\u0442\u0440\u043E\u043A\u0430\u043C\u0438, \u043F\u0440\u0438\u043D\u0438\u043C\u0430\u0435\u0442\u0441\u044F \u0430\u0441\u0438\u043D\u0445\u0440\u043E\u043D\u043D\u043E.","docs.push.title":"5. \u0428\u043B\u044E\u0437 \u0434\u043E\u0441\u0442\u0430\u0432\u043A\u0438","docs.push.body":"<code>GET /push/gateway</code> \u2014 \u043A\u0430\u043D\u0430\u043B \u0434\u043B\u0438\u043D\u043D\u043E\u0433\u043E \u043E\u043F\u0440\u043E\u0441\u0430 \u0434\u043B\u044F \u043E\u043F\u043E\u0432\u0435\u0449\u0435\u043D\u0438\u0439 \u043E \u043A\u0432\u043E\u0442\u0430\u0445 \u0438 \u0437\u0430\u0434\u0435\u0440\u0436\u043A\u0430\u0445. \u041F\u043E\u0434\u043F\u0438\u0448\u0438\u0442\u0435\u0441\u044C \u043E\u0434\u0438\u043D \u0440\u0430\u0437 \u0438 \u0434\u0435\u0440\u0436\u0438\u0442\u0435 \u0441\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0435 \u043E\u0442\u043A\u0440\u044B\u0442\u044B\u043C.","docs.ref.title":"\u0421\u043F\u0440\u0430\u0432\u043E\u0447\u043D\u0438\u043A","docs.th.method":"\u041C\u0435\u0442\u043E\u0434","docs.th.path":"\u041F\u0443\u0442\u044C","docs.th.auth":"\u0410\u0443\u0442\u0435\u043D\u0442\u0438\u0444\u0438\u043A\u0430\u0446\u0438\u044F","docs.th.purpose":"\u041D\u0430\u0437\u043D\u0430\u0447\u0435\u043D\u0438\u0435","docs.cat.models":"\u041A\u0430\u0442\u0430\u043B\u043E\u0433 \u043C\u043E\u0434\u0435\u043B\u0435\u0439","docs.cat.chat":"\u041A\u043E\u043C\u043F\u043B\u0438\u0448\u0435\u043D\u044B","docs.cat.events":"\u041F\u043E\u0442\u043E\u043A \u0441\u043E\u0431\u044B\u0442\u0438\u0439 \u0442\u0440\u0430\u0441\u0441\u0438\u0440\u043E\u0432\u043A\u0438","docs.cat.telemetry":"\u041F\u0440\u0438\u0451\u043C \u0441\u043F\u0430\u043D\u043E\u0432 \u0438 \u043C\u0435\u0442\u0440\u0438\u043A","docs.cat.push":"\u041F\u043E\u0434\u043F\u0438\u0441\u043A\u0430 \u043D\u0430 \u043E\u043F\u043E\u0432\u0435\u0449\u0435\u043D\u0438\u044F","docs.cat.health":"\u041F\u0440\u043E\u0432\u0435\u0440\u043A\u0430 \u0436\u0438\u0432\u043E\u0441\u0442\u0438","docs.authval.public":"\u041E\u0442\u043A\u0440\u044B\u0442\u044B\u0439","docs.error.title":"\u0424\u043E\u0440\u043C\u0430\u0442 \u043E\u0448\u0438\u0431\u043A\u0438","docs.error.body":'{"error":{"message":"\u041E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442 \u043A\u043B\u044E\u0447 API.","type":"invalid_request_error","param":null,"code":"missing_api_key"}}',"status.h1":"\u0421\u0442\u0430\u0442\u0443\u0441","status.ok":"\u0412\u0441\u0435 \u0441\u0438\u0441\u0442\u0435\u043C\u044B \u0440\u0430\u0431\u043E\u0442\u0430\u044E\u0442","status.checked":"\u043F\u0440\u043E\u0432\u0435\u0440\u0435\u043D\u043E \u0442\u043E\u043B\u044C\u043A\u043E \u0447\u0442\u043E","status.th.component":"\u041A\u043E\u043C\u043F\u043E\u043D\u0435\u043D\u0442","status.th.uptime":"\u0414\u043E\u0441\u0442\u0443\u043F\u043D\u043E\u0441\u0442\u044C (30 \u0434\u043D\u0435\u0439)","status.th.state":"\u0421\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u0435","status.comp.chat":"\u0427\u0430\u0442-\u043A\u043E\u043C\u043F\u043B\u0438\u0448\u0435\u043D\u044B","status.comp.events":"\u041F\u043E\u0442\u043E\u043A\u0438 \u0441\u043E\u0431\u044B\u0442\u0438\u0439","status.comp.telemetry":"\u041F\u0440\u0438\u0451\u043C \u0442\u0435\u043B\u0435\u043C\u0435\u0442\u0440\u0438\u0438","status.comp.push":"\u0428\u043B\u044E\u0437 \u0434\u043E\u0441\u0442\u0430\u0432\u043A\u0438","status.comp.edge":"\u041F\u0435\u0440\u0438\u0444\u0435\u0440\u0438\u0439\u043D\u044B\u0439 API","status.value.operational":"\u0420\u0430\u0431\u043E\u0442\u0430\u0435\u0442","status.incidents.title":"\u041F\u0440\u043E\u0448\u043B\u044B\u0435 \u0438\u043D\u0446\u0438\u0434\u0435\u043D\u0442\u044B","status.incidents.body":"\u0417\u0430 \u043F\u043E\u0441\u043B\u0435\u0434\u043D\u0438\u0435 30 \u0434\u043D\u0435\u0439 \u0438\u043D\u0446\u0438\u0434\u0435\u043D\u0442\u043E\u0432 \u043D\u0435 \u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043E\u0432\u0430\u043D\u043E. \u041E \u043F\u043B\u0430\u043D\u043E\u0432\u044B\u0445 \u0440\u0430\u0431\u043E\u0442\u0430\u0445 \u0441\u043E\u043E\u0431\u0449\u0430\u0435\u0442\u0441\u044F \u043C\u0438\u043D\u0438\u043C\u0443\u043C \u0437\u0430 72 \u0447\u0430\u0441\u0430.","about.h1":"\u041E Lumen","about.lead":"Lumen Labs \u0441\u043E\u0437\u0434\u0430\u0451\u0442 \u043D\u0435\u0431\u043E\u043B\u044C\u0448\u0443\u044E \u043F\u043B\u0430\u0442\u0444\u043E\u0440\u043C\u0443 \u043D\u0430 \u043F\u0435\u0440\u0438\u0444\u0435\u0440\u0438\u0438 \u0441 \u0447\u0451\u0442\u043A\u043E\u0439 \u043F\u043E\u0437\u0438\u0446\u0438\u0435\u0439 \u0434\u043B\u044F \u043A\u043E\u043C\u0430\u043D\u0434, \u043A\u043E\u0442\u043E\u0440\u044B\u0435 \u0432\u044B\u043F\u0443\u0441\u043A\u0430\u044E\u0442 \u0438\u043D\u0444\u0435\u0440\u0435\u043D\u0441 \u0438 \u043D\u0430\u0431\u043B\u044E\u0434\u0430\u0435\u043C\u043E\u0441\u0442\u044C \u0432\u043C\u0435\u0441\u0442\u0435. \u041C\u044B \u0434\u0435\u0440\u0436\u0438\u043C \u0448\u043B\u044E\u0437, \u043A\u043E\u043D\u0432\u0435\u0439\u0435\u0440 \u0441\u043E\u0431\u044B\u0442\u0438\u0439 \u0438 \u0441\u0431\u043E\u0440\u0449\u0438\u043A \u0442\u0435\u043B\u0435\u043C\u0435\u0442\u0440\u0438\u0438 \u0432 \u043E\u0434\u043D\u043E\u0439 \u0441\u0435\u0442\u0438, \u0447\u0442\u043E\u0431\u044B \u0437\u0430\u0434\u0435\u0440\u0436\u043A\u0430, \u0441\u0442\u043E\u0438\u043C\u043E\u0441\u0442\u044C \u0438 \u0434\u0430\u043D\u043D\u044B\u0435 \u0442\u0440\u0430\u0441\u0441\u0438\u0440\u043E\u0432\u043A\u0438 \u043E\u0441\u0442\u0430\u0432\u0430\u043B\u0438\u0441\u044C \u0432 \u043E\u0434\u043D\u043E\u043C \u043C\u0435\u0441\u0442\u0435.","about.what.title":"\u0427\u0442\u043E \u043C\u044B \u0434\u0435\u043B\u0430\u0435\u043C","about.what.body":"\u041D\u0430\u0448\u0438 \u043A\u043B\u0438\u0435\u043D\u0442\u044B \u2014 \u043F\u0440\u043E\u0434\u0443\u043A\u0442\u043E\u0432\u044B\u0435 \u043A\u043E\u043C\u0430\u043D\u0434\u044B, \u044D\u043A\u0441\u043F\u043B\u0443\u0430\u0442\u0438\u0440\u0443\u044E\u0449\u0438\u0435 \u0430\u0441\u0441\u0438\u0441\u0442\u0435\u043D\u0442\u043E\u0432, \u0430\u0433\u0435\u043D\u0442\u043D\u044B\u0435 \u0441\u0446\u0435\u043D\u0430\u0440\u0438\u0438 \u0438 \u0444\u043E\u043D\u043E\u0432\u044B\u0435 \u0437\u0430\u0434\u0430\u0447\u0438. \u0414\u043B\u044F \u043D\u0438\u0445 \u0432\u0430\u0436\u043D\u044B p95 \u0437\u0430\u0434\u0435\u0440\u0436\u043A\u0438, \u043A\u0432\u043E\u0442\u044B \u043D\u0430 \u0430\u0440\u0435\u043D\u0434\u0430\u0442\u043E\u0440\u0430 \u0438 \u0432\u043E\u0437\u043C\u043E\u0436\u043D\u043E\u0441\u0442\u044C \u0432\u043E\u0441\u043F\u0440\u043E\u0438\u0437\u0432\u0435\u0441\u0442\u0438 \u043B\u044E\u0431\u043E\u0439 \u0437\u0430\u043F\u0440\u043E\u0441 \u043F\u0440\u0438 \u0441\u0431\u043E\u0435.","about.contact.title":"\u041A\u043E\u043D\u0442\u0430\u043A\u0442\u044B","about.contact.body":'\u0412\u043E\u043F\u0440\u043E\u0441\u044B \u043F\u043E\u0434\u0434\u0435\u0440\u0436\u043A\u0438 \u0438 \u0431\u0435\u0437\u043E\u043F\u0430\u0441\u043D\u043E\u0441\u0442\u0438: <a href="mailto:support@lumenlabs.example">support@lumenlabs.example</a>. \u041E\u0431\u043D\u043E\u0432\u043B\u0435\u043D\u0438\u044F \u043E\u0431 \u0438\u043D\u0446\u0438\u0434\u0435\u043D\u0442\u0430\u0445 \u043F\u0443\u0431\u043B\u0438\u043A\u0443\u0435\u043C \u043D\u0430 <a href="/status">\u0441\u0442\u0440\u0430\u043D\u0438\u0446\u0435 \u0441\u0442\u0430\u0442\u0443\u0441\u0430</a>, \u0430 \u0432\u0441\u0435 \u044D\u043D\u0434\u043F\u043E\u0438\u043D\u0442\u044B \u043E\u043F\u0438\u0441\u0430\u043D\u044B \u0432 <a href="/docs">\u0441\u043F\u0440\u0430\u0432\u043E\u0447\u043D\u0438\u043A\u0435 API</a>.',"privacy.h1":"\u041F\u043E\u043B\u0438\u0442\u0438\u043A\u0430 \u043A\u043E\u043D\u0444\u0438\u0434\u0435\u043D\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0441\u0442\u0438","privacy.updated":"\u041E\u0431\u043D\u043E\u0432\u043B\u0435\u043D\u043E: 1 \u043C\u0430\u044F 2026 \u0433.","privacy.data.title":"\u041A\u0430\u043A\u0438\u0435 \u0434\u0430\u043D\u043D\u044B\u0435 \u043C\u044B \u043E\u0431\u0440\u0430\u0431\u0430\u0442\u044B\u0432\u0430\u0435\u043C","privacy.data.body":"\u041C\u0435\u0442\u0430\u0434\u0430\u043D\u043D\u044B\u0435 \u0437\u0430\u043F\u0440\u043E\u0441\u043E\u0432 (\u043C\u0435\u0442\u043A\u0438 \u0432\u0440\u0435\u043C\u0435\u043D\u0438, \u043A\u043E\u0434\u044B \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F, \u0447\u0438\u0441\u043B\u043E \u0442\u043E\u043A\u0435\u043D\u043E\u0432) \u0445\u0440\u0430\u043D\u044F\u0442\u0441\u044F 30 \u0434\u043D\u0435\u0439 \u0434\u043B\u044F \u0431\u0438\u043B\u043B\u0438\u043D\u0433\u0430 \u0438 \u043D\u0430\u0434\u0451\u0436\u043D\u043E\u0441\u0442\u0438. \u0421\u043E\u0434\u0435\u0440\u0436\u0438\u043C\u043E\u0435 \u0437\u0430\u043F\u0440\u043E\u0441\u043E\u0432 \u0438 \u043E\u0442\u0432\u0435\u0442\u043E\u0432 \u043D\u0435 \u0441\u043E\u0445\u0440\u0430\u043D\u044F\u0435\u0442\u0441\u044F, \u0435\u0441\u043B\u0438 \u0430\u0434\u043C\u0438\u043D\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440 \u0440\u0430\u0431\u043E\u0447\u0435\u0433\u043E \u043F\u0440\u043E\u0441\u0442\u0440\u0430\u043D\u0441\u0442\u0432\u0430 \u044F\u0432\u043D\u043E \u043D\u0435 \u0432\u043A\u043B\u044E\u0447\u0438\u043B \u043B\u043E\u0433\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u0435 \u0437\u0430\u043F\u0440\u043E\u0441\u043E\u0432.","privacy.cookies.title":"\u0424\u0430\u0439\u043B\u044B cookie","privacy.cookies.body":"\u0421\u0430\u0439\u0442 \u043D\u0435 \u0443\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0435\u0442 \u0440\u0435\u043A\u043B\u0430\u043C\u043D\u044B\u0435 \u0438\u043B\u0438 \u0430\u043D\u0430\u043B\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u0438\u0435 cookie. \u0421\u0435\u0441\u0441\u0438\u043E\u043D\u043D\u044B\u0435 cookie \u0432\u044B\u0434\u0430\u044E\u0442\u0441\u044F \u0442\u043E\u043B\u044C\u043A\u043E \u0432\u043D\u0443\u0442\u0440\u0438 \u043A\u043E\u043D\u0441\u043E\u043B\u0438 \u043F\u043E\u0441\u043B\u0435 \u0432\u0445\u043E\u0434\u0430.","privacy.third.title":"\u0422\u0440\u0435\u0442\u044C\u0438 \u0441\u0442\u043E\u0440\u043E\u043D\u044B","privacy.third.body":"\u041C\u044B \u043D\u0435 \u043F\u0440\u043E\u0434\u0430\u0451\u043C \u0434\u0430\u043D\u043D\u044B\u0435. \u0418\u043D\u0444\u0440\u0430\u0441\u0442\u0440\u0443\u043A\u0442\u0443\u0440\u043D\u044B\u0435 \u043F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440\u044B \u043E\u0431\u0440\u0430\u0431\u0430\u0442\u044B\u0432\u0430\u044E\u0442 \u0442\u0440\u0430\u0444\u0438\u043A \u043E\u0442 \u043D\u0430\u0448\u0435\u0433\u043E \u0438\u043C\u0435\u043D\u0438 \u043D\u0430 \u0441\u0442\u0430\u043D\u0434\u0430\u0440\u0442\u043D\u044B\u0445 \u0443\u0441\u043B\u043E\u0432\u0438\u044F\u0445 \u043E\u0431\u0440\u0430\u0431\u043E\u0442\u043A\u0438 \u0434\u0430\u043D\u043D\u044B\u0445.","privacy.contact.title":"\u041A\u043E\u043D\u0442\u0430\u043A\u0442\u044B","privacy.contact.body":'\u0412\u043E\u043F\u0440\u043E\u0441\u044B \u043E \u043A\u043E\u043D\u0444\u0438\u0434\u0435\u043D\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0441\u0442\u0438 \u2014 \u043D\u0430 <a href="mailto:privacy@lumenlabs.example">privacy@lumenlabs.example</a>.',"nf.h1":"\u0421\u0442\u0440\u0430\u043D\u0438\u0446\u0430 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u0430","nf.body":"\u0417\u0430\u043F\u0440\u043E\u0448\u0435\u043D\u043D\u0430\u044F \u0441\u0442\u0440\u0430\u043D\u0438\u0446\u0430 \u043D\u0435 \u0441\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u0435\u0442 \u0438\u043B\u0438 \u0431\u044B\u043B\u0430 \u043F\u0435\u0440\u0435\u043C\u0435\u0449\u0435\u043D\u0430. \u041F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435 \u0430\u0434\u0440\u0435\u0441 \u0438\u043B\u0438 \u043D\u0430\u0447\u043D\u0438\u0442\u0435 \u0441 \u043E\u0434\u043D\u043E\u0433\u043E \u0438\u0437 \u0440\u0430\u0437\u0434\u0435\u043B\u043E\u0432:","nf.home":"\u0413\u043B\u0430\u0432\u043D\u0430\u044F","nf.docs":"\u0414\u043E\u043A\u0443\u043C\u0435\u043D\u0442\u0430\u0446\u0438\u044F","nf.status":"\u0421\u0442\u0430\u0442\u0443\u0441","signin.h1":"\u0412\u0445\u043E\u0434","signin.lead":"\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u0443\u0447\u0451\u0442\u043D\u044B\u0435 \u0434\u0430\u043D\u043D\u044B\u0435 \u0440\u0430\u0431\u043E\u0447\u0435\u0433\u043E \u043F\u0440\u043E\u0441\u0442\u0440\u0430\u043D\u0441\u0442\u0432\u0430.","signin.id":"ID \u0440\u0430\u0431\u043E\u0447\u0435\u0433\u043E \u043F\u0440\u043E\u0441\u0442\u0440\u0430\u043D\u0441\u0442\u0432\u0430","signin.key":"\u041A\u043B\u044E\u0447 \u0434\u043E\u0441\u0442\u0443\u043F\u0430","signin.submit":"\u041F\u0440\u043E\u0434\u043E\u043B\u0436\u0438\u0442\u044C","signin.note":"\u0423\u0447\u0451\u0442\u043D\u044B\u0435 \u0434\u0430\u043D\u043D\u044B\u0435 \u043F\u0440\u043E\u0432\u0435\u0440\u044F\u044E\u0442\u0441\u044F \u043D\u0430 \u0441\u0435\u0440\u0432\u0435\u0440\u0435.","signin.err":"\u0423\u0447\u0451\u0442\u043D\u044B\u0435 \u0434\u0430\u043D\u043D\u044B\u0435 \u043D\u0435 \u0441\u043E\u0432\u043F\u0430\u0434\u0430\u044E\u0442 \u0441 \u0437\u0430\u043F\u0438\u0441\u044F\u043C\u0438.","signin.limited":"\u0421\u043B\u0438\u0448\u043A\u043E\u043C \u043C\u043D\u043E\u0433\u043E \u043F\u043E\u043F\u044B\u0442\u043E\u043A. \u041F\u043E\u0432\u0442\u043E\u0440\u0438\u0442\u0435 \u043F\u043E\u0437\u0436\u0435.","signin.net":"\u041E\u0448\u0438\u0431\u043A\u0430 \u0441\u0435\u0442\u0438. \u041F\u043E\u0432\u0442\u043E\u0440\u0438\u0442\u0435 \u043F\u043E\u043F\u044B\u0442\u043A\u0443."}};var BRAND="Lumen";var LAYER_CSS=`
:root{--bg:#fff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--accent:#4f46e5;--accent-hover:#4338ca;--soft:#f8fafc}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;line-height:1.65;font-size:15px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:960px;margin:0 auto;padding:0 24px}
header.nav{border-bottom:1px solid var(--line);position:sticky;top:0;background:rgba(255,255,255,.92);backdrop-filter:blur(8px);z-index:10}
header.nav .wrap{display:flex;align-items:center;justify-content:space-between;height:62px;gap:14px}
.brand{display:flex;align-items:center;gap:9px;font-weight:700;font-size:16px;color:var(--ink)}
.brand:hover{text-decoration:none}
.brand svg{width:22px;height:22px}
nav a{margin-left:24px;color:var(--muted);font-size:14px}
nav a:hover{color:var(--ink);text-decoration:none}
.navright{display:flex;align-items:center;gap:14px;margin-left:auto}
.lang{display:flex;gap:2px;border:1px solid var(--line);border-radius:9px;padding:2px;background:var(--soft)}
.lang button{border:0;background:transparent;color:var(--muted);font:12px/1 inherit;padding:6px 8px;border-radius:7px;cursor:pointer;transition:background .15s,color .15s}
.lang button:hover{color:var(--ink);background:#eef2ff}
.lang button[aria-pressed="true"]{background:var(--accent);color:#fff}
.lang button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.hero{padding:84px 0 56px;text-align:center}
.hero h1{font-size:42px;line-height:1.15;margin:0 0 18px;letter-spacing:-.02em}
.hero p{font-size:17px;color:var(--muted);max-width:640px;margin:0 auto 26px}
.pill{display:inline-block;font-size:12px;color:var(--accent);background:#eef2ff;border:1px solid #e0e7ff;border-radius:999px;padding:4px 12px;margin-bottom:20px}
.btn{display:inline-block;padding:11px 20px;border-radius:8px;background:var(--accent);color:#fff;font-size:14px;font-weight:600}
.btn:hover{background:var(--accent-hover);text-decoration:none}
.btn.ghost{background:#fff;color:var(--ink);border:1px solid var(--line);margin-left:10px}
.btn.ghost:hover{background:var(--soft)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px}
.card{border:1px solid var(--line);border-radius:12px;padding:20px}
.card h3{margin:0 0 6px;font-size:15px}
.card p{margin:0;color:var(--muted);font-size:13.5px}
.section{padding:44px 0 60px}
.section h2{font-size:22px;margin:0 0 10px}
.section p{color:var(--muted)}
pre{background:#0f172a;color:#e2e8f0;border-radius:10px;padding:18px 20px;overflow-x:auto;font-size:12.5px;line-height:1.75;text-align:left;margin:16px 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
main.doc{padding:52px 0 72px}
main.doc h1{font-size:32px;margin:0 0 8px}
main.doc h2{font-size:19px;margin:36px 0 8px;padding-top:18px;border-top:1px solid var(--line)}
main.doc p,main.doc li{color:var(--muted);font-size:14.5px}
main.doc code{background:var(--soft);border:1px solid var(--line);border-radius:5px;padding:1px 5px;font-size:13px;color:#334155}
table{width:100%;border-collapse:collapse;margin:14px 0;font-size:13.5px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
td code{font-size:12.5px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#16a34a;margin-right:7px}
.ok-text{color:#16a34a;font-weight:600}
footer{border-top:1px solid var(--line);padding:30px 0;color:var(--muted);font-size:13px}
footer .wrap{display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px}
footer a{color:var(--muted);margin-right:16px}
@media(max-width:720px){
  .hero h1{font-size:31px}
  .hero{padding:56px 0 36px}
  .section{padding:34px 0 44px}
  header.nav .wrap{height:auto;min-height:62px;flex-wrap:wrap;padding:9px 0;gap:8px}
  .navright{width:100%;justify-content:space-between;gap:8px}
  nav{display:flex;flex-wrap:wrap;gap:12px}
  nav a{margin-left:0;font-size:13px}
  .lang button{padding:5px 7px}
  .signin{padding:48px 0 64px}
}
/* \u901A\u7528\u767B\u5F55\u9875\uFF1A\u53EA\u63CF\u8FF0\u51ED\u8BC1\uFF0C\u4E0D\u51FA\u73B0\u4EFB\u4F55\u5185\u90E8\u7CFB\u7EDF\u6807\u8BC6 */
.signin{padding:76px 0 88px}
.signin .wrap{max-width:420px}
.signin h1{font-size:26px;margin:0 0 8px;letter-spacing:-.01em}
.signin .lead{color:var(--muted);font-size:14.5px;margin:0 0 26px}
.signin form{display:grid;gap:14px}
.signin label{display:block;font-size:12.5px;color:var(--muted);font-weight:600;margin-bottom:6px}
.signin input{width:100%;height:42px;padding:0 12px;border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--ink);font:14px/1.4 inherit;outline:none;transition:border-color .15s,box-shadow .15s}
.signin input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(79,70,229,.15)}
.signin button{height:44px;border:0;border-radius:8px;background:var(--accent);color:#fff;font-size:14px;font-weight:600;cursor:pointer;transition:background .15s}
.signin button:hover{background:var(--accent-hover)}
.signin button:disabled{opacity:.65;cursor:default}
.signin .err{min-height:18px;color:#dc2626;font-size:12.5px}
.signin .note{color:var(--muted);font-size:12.5px;margin:18px 0 0}
@media(max-width:720px){
  .signin{padding:48px 0 64px}
}
`;var LOGO='<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="9" stroke="#4f46e5" stroke-width="2"/><path d="M12 7v5.2l3.2 2" stroke="#4f46e5" stroke-width="2" stroke-linecap="round"/></svg>';var esc=s=>String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");var t=key=>esc(MESSAGES[DEFAULT_LANG][key]??key);var h=key=>MESSAGES[DEFAULT_LANG][key]??"";var ti=key=>`data-i18n="${key}"`;var thi=key=>`data-i18n-html="${key}"`;var safeJson=value=>JSON.stringify(value).replace(/</g,"\\u003c");var LANGS_JSON=safeJson(LANGS.map(l=>({code:l.code,html:l.htmlLang})));var pickMessages=keys=>{if(!keys)return MESSAGES;const out={};for(const[code,dict]of Object.entries(MESSAGES)){const picked={};for(const key of keys){if(dict[key]!=null)picked[key]=dict[key]}out[code]=picked}return out};var langBar=()=>`<div class="lang" role="group" data-i18n-aria="lang.aria" aria-label="${t("lang.aria")}">${LANGS.map(l=>`<button type="button" data-lang="${l.code}" aria-pressed="${l.code===DEFAULT_LANG?"true":"false"}">${l.short}</button>`).join("")}</div>`;var i18nScript=(meta,keys=null)=>`<script>
(function () {
  var KEY = 'lumen.lang';
  var DEF = '${DEFAULT_LANG}';
  var LANGS = ${LANGS_JSON};
  var M = ${safeJson(pickMessages(keys))};
  var META = ${safeJson(meta)};

  function stored() {
    try { return localStorage.getItem(KEY) || DEF; } catch (e) { return DEF; }
  }
  function remember(lang) {
    try { localStorage.setItem(KEY, lang); } catch (e) {}
  }
  function paint(lang) {
    var d = M[lang] || M[DEF];
    var els;

    els = document.querySelectorAll('[data-i18n]');
    for (var i = 0; i < els.length; i++) {
      var k = els[i].getAttribute('data-i18n');
      if (d[k] != null) els[i].textContent = d[k];
    }

    els = document.querySelectorAll('[data-i18n-html]');
    for (var j = 0; j < els.length; j++) {
      var k2 = els[j].getAttribute('data-i18n-html');
      if (d[k2] != null) els[j].innerHTML = d[k2];
    }

    els = document.querySelectorAll('[data-i18n-aria]');
    for (var n = 0; n < els.length; n++) {
      var k3 = els[n].getAttribute('data-i18n-aria');
      if (d[k3] != null) els[n].setAttribute('aria-label', d[k3]);
    }

    for (var q = 0; q < LANGS.length; q++) {
      if (LANGS[q].code === lang) { document.documentElement.lang = LANGS[q].html; break; }
    }
    if (META.title && d[META.title]) document.title = d[META.title];
    if (META.desc && d[META.desc]) {
      var md = document.querySelector('meta[name="description"]');
      if (md) md.setAttribute('content', d[META.desc]);
    }

    els = document.querySelectorAll('[data-lang]');
    for (var b = 0; b < els.length; b++) {
      els[b].setAttribute('aria-pressed', els[b].getAttribute('data-lang') === lang ? 'true' : 'false');
    }
  }

  /* \u9875\u9762\u811A\u672C\uFF08\u5982\u767B\u5F55\u9519\u8BEF\u63D0\u793A\uFF09\u6309\u5F53\u524D\u8BED\u8A00\u53D6\u6587\u6848 */
  window.__lumenT = function (key) {
    var lang = stored();
    var d = M[lang] || M[DEF];
    return d[key] != null ? d[key] : '';
  };

  var cur = stored();
  if (!M[cur]) cur = DEF;
  paint(cur);

  document.addEventListener('click', function (e) {
    var el = e.target;
    while (el && el !== document) {
      if (el.getAttribute && el.getAttribute('data-lang')) break;
      el = el.parentNode;
    }
    if (!el || !el.getAttribute) return;
    var lang = el.getAttribute('data-lang');
    if (!lang || !M[lang]) return;
    remember(lang);
    paint(lang);
  });
})();
</script>`;var layout=({title,desc,body,meta,script="",localeKeys=null})=>`<!DOCTYPE html>
<html lang="${DEFAULT_LANG}"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<meta name="description" content="${desc}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>${LAYER_CSS}</style>
</head><body>
<header class="nav"><div class="wrap">
<a class="brand" href="/">${LOGO}${BRAND}</a>
<div class="navright">
<nav><a href="/docs" ${ti("nav.docs")}>${t("nav.docs")}</a><a href="/status" ${ti("nav.status")}>${t("nav.status")}</a><a href="/about" ${ti("nav.about")}>${t("nav.about")}</a><a href="/privacy" ${ti("nav.privacy")}>${t("nav.privacy")}</a></nav>
${langBar()}
</div>
</div></header>
${body}
<footer><div class="wrap"><span>&copy; 2026 ${BRAND} Labs &middot; <span ${ti("footer.tagline")}>${t("footer.tagline")}</span></span><span><a href="/docs" ${ti("nav.docs")}>${t("nav.docs")}</a><a href="/status" ${ti("nav.status")}>${t("nav.status")}</a><a href="/about" ${ti("nav.about")}>${t("nav.about")}</a><a href="/privacy" ${ti("nav.privacy")}>${t("nav.privacy")}</a></span></div></footer>
${i18nScript(meta,localeKeys)}
${script}
</body></html>`;var HOME=origin=>`
<section class="hero"><div class="wrap">
<span class="pill" ${ti("home.pill")}>${t("home.pill")}</span>
<h1 ${ti("home.h1")}>${t("home.h1")}</h1>
<p ${ti("home.lead")}>${t("home.lead")}</p>
<p><a class="btn" href="/docs" ${ti("home.cta.primary")}>${t("home.cta.primary")}</a><a class="btn ghost" href="/status" ${ti("home.cta.secondary")}>${t("home.cta.secondary")}</a></p>
</div></section>
<div class="wrap section">
<div class="grid">
<div class="card"><h3 ${ti("home.card1.title")}>${t("home.card1.title")}</h3><p ${thi("home.card1.body")}>${h("home.card1.body")}</p></div>
<div class="card"><h3 ${ti("home.card2.title")}>${t("home.card2.title")}</h3><p ${thi("home.card2.body")}>${h("home.card2.body")}</p></div>
<div class="card"><h3 ${ti("home.card3.title")}>${t("home.card3.title")}</h3><p ${thi("home.card3.body")}>${h("home.card3.body")}</p></div>
<div class="card"><h3 ${ti("home.card4.title")}>${t("home.card4.title")}</h3><p ${thi("home.card4.body")}>${h("home.card4.body")}</p></div>
</div>
<h2 style="margin-top:38px" ${ti("home.single.title")}>${t("home.single.title")}</h2>
<p ${ti("home.single.lead")}>${t("home.single.lead")}</p>
<pre><code>curl -s ${origin}/api/v1/chat \\
  -H "Authorization: Bearer $LUMEN_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"model":"lumen-1-mini","messages":[{"role":"user","content":"Hello"}]}'</code></pre>
<p ${thi("home.single.note")}>${h("home.single.note")}</p>
</div>`;var DOCS=origin=>`
<main class="doc"><div class="wrap">
<h1 ${ti("docs.h1")}>${t("docs.h1")}</h1>
<p ${ti("docs.lead")}>${t("docs.lead")}</p>

<h2 ${ti("docs.auth.title")}>${t("docs.auth.title")}</h2>
<p ${thi("docs.auth.body")}>${h("docs.auth.body")}</p>
<pre><code>Authorization: Bearer $LUMEN_KEY</code></pre>

<h2 ${ti("docs.chat.title")}>${t("docs.chat.title")}</h2>
<p ${thi("docs.chat.body")}>${h("docs.chat.body")}</p>
<pre><code>curl -s ${origin}/api/v1/chat \\
  -H "Authorization: Bearer $LUMEN_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"model":"lumen-1-mini","stream":true,"messages":[{"role":"user","content":"Summarise this trace"}]}'</code></pre>

<h2 ${ti("docs.events.title")}>${t("docs.events.title")}</h2>
<p ${thi("docs.events.body")}>${h("docs.events.body")}</p>

<h2 ${ti("docs.telemetry.title")}>${t("docs.telemetry.title")}</h2>
<p ${thi("docs.telemetry.body")}>${h("docs.telemetry.body")}</p>
<pre><code>curl -s ${origin}/telemetry/ingest \\
  -H "Authorization: Bearer $LUMEN_KEY" \\
  -H "Content-Type: application/x-ndjson" \\
  --data-binary @spans.ndjson</code></pre>

<h2 ${ti("docs.push.title")}>${t("docs.push.title")}</h2>
<p ${thi("docs.push.body")}>${h("docs.push.body")}</p>

<h2 ${ti("docs.ref.title")}>${t("docs.ref.title")}</h2>
<table>
<tr><th ${ti("docs.th.method")}>${t("docs.th.method")}</th><th ${ti("docs.th.path")}>${t("docs.th.path")}</th><th ${ti("docs.th.auth")}>${t("docs.th.auth")}</th><th ${ti("docs.th.purpose")}>${t("docs.th.purpose")}</th></tr>
<tr><td><code>GET</code></td><td><code>/api/v1/models</code></td><td ${ti("docs.authval.public")}>${t("docs.authval.public")}</td><td ${ti("docs.cat.models")}>${t("docs.cat.models")}</td></tr>
<tr><td><code>POST</code></td><td><code>/api/v1/chat</code></td><td>Bearer</td><td ${ti("docs.cat.chat")}>${t("docs.cat.chat")}</td></tr>
<tr><td><code>GET</code></td><td><code>/api/v2beta/events</code></td><td>Bearer</td><td ${ti("docs.cat.events")}>${t("docs.cat.events")}</td></tr>
<tr><td><code>POST</code></td><td><code>/telemetry/ingest</code></td><td>Bearer</td><td ${ti("docs.cat.telemetry")}>${t("docs.cat.telemetry")}</td></tr>
<tr><td><code>GET</code></td><td><code>/push/gateway</code></td><td>Bearer</td><td ${ti("docs.cat.push")}>${t("docs.cat.push")}</td></tr>
<tr><td><code>GET</code></td><td><code>/health</code></td><td ${ti("docs.authval.public")}>${t("docs.authval.public")}</td><td ${ti("docs.cat.health")}>${t("docs.cat.health")}</td></tr>
</table>

<h2 ${ti("docs.error.title")}>${t("docs.error.title")}</h2>
<pre><code ${ti("docs.error.body")}>${t("docs.error.body")}</code></pre>
</div></main>`;var STATUS=`
<main class="doc"><div class="wrap">
<h1 ${ti("status.h1")}>${t("status.h1")}</h1>
<p><span class="dot"></span><span class="ok-text" ${ti("status.ok")}>${t("status.ok")}</span> &middot; <span ${ti("status.checked")}>${t("status.checked")}</span></p>
<table>
<tr><th ${ti("status.th.component")}>${t("status.th.component")}</th><th ${ti("status.th.uptime")}>${t("status.th.uptime")}</th><th ${ti("status.th.state")}>${t("status.th.state")}</th></tr>
<tr><td ${ti("status.comp.chat")}>${t("status.comp.chat")}</td><td>99.98%</td><td><span class="dot"></span><span ${ti("status.value.operational")}>${t("status.value.operational")}</span></td></tr>
<tr><td ${ti("status.comp.events")}>${t("status.comp.events")}</td><td>99.97%</td><td><span class="dot"></span><span ${ti("status.value.operational")}>${t("status.value.operational")}</span></td></tr>
<tr><td ${ti("status.comp.telemetry")}>${t("status.comp.telemetry")}</td><td>99.99%</td><td><span class="dot"></span><span ${ti("status.value.operational")}>${t("status.value.operational")}</span></td></tr>
<tr><td ${ti("status.comp.push")}>${t("status.comp.push")}</td><td>100.00%</td><td><span class="dot"></span><span ${ti("status.value.operational")}>${t("status.value.operational")}</span></td></tr>
<tr><td ${ti("status.comp.edge")}>${t("status.comp.edge")}</td><td>99.98%</td><td><span class="dot"></span><span ${ti("status.value.operational")}>${t("status.value.operational")}</span></td></tr>
</table>
<h2 ${ti("status.incidents.title")}>${t("status.incidents.title")}</h2>
<p ${ti("status.incidents.body")}>${t("status.incidents.body")}</p>
</div></main>`;var ABOUT=`
<main class="doc"><div class="wrap">
<h1 ${ti("about.h1")}>${t("about.h1")}</h1>
<p ${ti("about.lead")}>${t("about.lead")}</p>
<h2 ${ti("about.what.title")}>${t("about.what.title")}</h2>
<p ${ti("about.what.body")}>${t("about.what.body")}</p>
<h2 ${ti("about.contact.title")}>${t("about.contact.title")}</h2>
<p ${thi("about.contact.body")}>${h("about.contact.body")}</p>
</div></main>`;var PRIVACY=`
<main class="doc"><div class="wrap">
<h1 ${ti("privacy.h1")}>${t("privacy.h1")}</h1>
<p ${ti("privacy.updated")}>${t("privacy.updated")}</p>
<h2 ${ti("privacy.data.title")}>${t("privacy.data.title")}</h2>
<p ${ti("privacy.data.body")}>${t("privacy.data.body")}</p>
<h2 ${ti("privacy.cookies.title")}>${t("privacy.cookies.title")}</h2>
<p ${ti("privacy.cookies.body")}>${t("privacy.cookies.body")}</p>
<h2 ${ti("privacy.third.title")}>${t("privacy.third.title")}</h2>
<p ${ti("privacy.third.body")}>${t("privacy.third.body")}</p>
<h2 ${ti("privacy.contact.title")}>${t("privacy.contact.title")}</h2>
<p ${thi("privacy.contact.body")}>${h("privacy.contact.body")}</p>
</div></main>`;var NOT_FOUND_BODY=`
<main class="doc"><div class="wrap">
<h1 ${ti("nf.h1")}>${t("nf.h1")}</h1>
<p ${ti("nf.body")}>${t("nf.body")}</p>
<p><a class="btn" href="/" ${ti("nf.home")}>${t("nf.home")}</a><a class="btn ghost" href="/docs" ${ti("nf.docs")}>${t("nf.docs")}</a><a class="btn ghost" href="/status" ${ti("nf.status")}>${t("nf.status")}</a></p>
</div></main>`;var SIGNIN=`
<main class="signin"><div class="wrap">
<h1 ${ti("signin.h1")}>${t("signin.h1")}</h1>
<p class="lead" ${ti("signin.lead")}>${t("signin.lead")}</p>
<form id="signin-form" method="post" action="/auth" autocomplete="off" novalidate>
<input type="hidden" name="next" value="__NEXT__">
<div>
<label for="signin-id" ${ti("signin.id")}>${t("signin.id")}</label>
<input id="signin-id" name="id" type="text" spellcheck="false" autocapitalize="off" autocomplete="off" required>
</div>
<div>
<label for="signin-key" ${ti("signin.key")}>${t("signin.key")}</label>
<input id="signin-key" name="key" type="password" autocomplete="off" required>
</div>
<div id="signin-err" class="err" role="alert" aria-live="polite">__ERR__</div>
<button type="submit" id="signin-btn" ${ti("signin.submit")}>${t("signin.submit")}</button>
<p class="note" ${ti("signin.note")}>${t("signin.note")}</p>
</form>
</div></main>`;var SIGNIN_KEYS=["meta.signin.title","meta.home.desc","nav.docs","nav.status","nav.about","nav.privacy","footer.tagline","lang.aria","signin.h1","signin.lead","signin.id","signin.key","signin.submit","signin.note","signin.err","signin.limited","signin.net"];var SIGNIN_SCRIPT=`<script>
(function () {
  var form = document.getElementById('signin-form');
  var err = document.getElementById('signin-err');
  var btn = document.getElementById('signin-btn');
  var idEl = document.getElementById('signin-id');
  var keyEl = document.getElementById('signin-key');

  function msg(key) {
    return window.__lumenT ? window.__lumenT(key) : '';
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    err.textContent = '';
    btn.disabled = true;
    fetch('/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ id: idEl.value, key: keyEl.value })
    }).then(function (r) {
      if (r.status === 204) { location.replace(location.href); return; }
      if (r.status === 401) {
        err.textContent = msg('signin.err');
        keyEl.value = '';
        keyEl.focus();
      } else if (r.status === 429) {
        err.textContent = msg('signin.limited');
      } else {
        err.textContent = msg('signin.net');
      }
    }).catch(function () {
      err.textContent = msg('signin.net');
    }).then(function () {
      btn.disabled = false;
    });
  });
})();
</script>`;var SIGNIN_HEADERS={"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store","X-Robots-Tag":"noindex","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer"};var renderSignin=(entry="1",failed=false)=>new Response(layout({title:t("meta.signin.title"),desc:t("meta.home.desc"),body:SIGNIN.replace("__NEXT__",entry==="2"?"2":"1").replace("__ERR__",failed?t("signin.err"):""),meta:{title:"meta.signin.title",desc:"meta.home.desc"},script:SIGNIN_SCRIPT,localeKeys:SIGNIN_KEYS}),{status:failed?401:200,headers:SIGNIN_HEADERS});var PAGES={"/":{meta:{title:"meta.home.title",desc:"meta.home.desc"},title:t("meta.home.title"),desc:t("meta.home.desc"),body:HOME},"/docs":{meta:{title:"meta.docs.title",desc:"meta.docs.desc"},title:t("meta.docs.title"),desc:t("meta.docs.desc"),body:DOCS},"/status":{meta:{title:"meta.status.title",desc:"meta.status.desc"},title:t("meta.status.title"),desc:t("meta.status.desc"),body:()=>STATUS},"/about":{meta:{title:"meta.about.title",desc:"meta.about.desc"},title:t("meta.about.title"),desc:t("meta.about.desc"),body:()=>ABOUT},"/privacy":{meta:{title:"meta.privacy.title",desc:"meta.privacy.desc"},title:t("meta.privacy.title"),desc:t("meta.privacy.desc"),body:()=>PRIVACY}};var SITE_META={title:t("meta.home.title"),desc:t("meta.home.desc"),brand:BRAND,h1:t("home.h1"),lead:t("home.lead")};var ICON_SVG='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#4f46e5"/><circle cx="16" cy="16" r="8" fill="none" stroke="#fff" stroke-width="2.5"/><path d="M16 10.5v5.8l3.6 2.2" stroke="#fff" stroke-width="2.5" stroke-linecap="round"/></svg>';var STATIC={"/favicon.svg":{type:"image/svg+xml",cache:"public, max-age=86400",body:()=>ICON_SVG},"/favicon.ico":{type:"image/svg+xml",cache:"public, max-age=86400",body:()=>ICON_SVG},"/robots.txt":{type:"text/plain; charset=utf-8",cache:"public, max-age=86400",body:url=>`User-agent: *
Allow: /
Sitemap: ${url.origin}/sitemap.xml
`},"/sitemap.xml":{type:"application/xml; charset=utf-8",cache:"public, max-age=86400",body:url=>{const paths=["/","/docs","/status","/about","/privacy"];const urls=paths.map(p=>`  <url><loc>${url.origin}${p}</loc><changefreq>weekly</changefreq></url>`).join("\n");return`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>
`}}};var PAGE_HEADERS={"Content-Type":"text/html; charset=utf-8","Cache-Control":"public, max-age=300","X-Content-Type-Options":"nosniff","Referrer-Policy":"same-origin"};var renderPage=(page,origin,status=200)=>new Response(layout({title:page.title,desc:page.desc,body:page.body(origin),meta:page.meta}),{status,headers:PAGE_HEADERS});var normalize=pathname=>pathname.length>1?pathname.replace(/\/+$/,"")||"/":pathname;var handleWeb=(request,url)=>{const path=normalize(url.pathname);const asset=STATIC[path];if(asset){return new Response(asset.body(url),{status:200,headers:{"Content-Type":asset.type,"Cache-Control":asset.cache,"X-Content-Type-Options":"nosniff"}})}const page=PAGES[path];if(page){if(request.method!=="GET"&&request.method!=="HEAD"){return new Response("Method Not Allowed",{status:405,headers:{...PAGE_HEADERS,Allow:"GET, HEAD"}})}return renderPage(page,url.origin)}return webNotFound(url)};var webNotFound=url=>renderPage({meta:{title:"meta.404.title",desc:"meta.404.desc"},title:t("meta.404.title"),desc:t("meta.404.desc"),body:()=>NOT_FOUND_BODY},url.origin,404);var JSON_HEADERS={"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"};var json=(status,body,extra={})=>new Response(JSON.stringify(body),{status,headers:{...JSON_HEADERS,...extra}});var authFailure=req=>{const hasAuth=req.headers.get("Authorization");const payload=hasAuth?{error:{message:"Incorrect API key provided. Keys are issued per workspace.",type:"invalid_request_error",param:null,code:"invalid_api_key"}}:{error:{message:"Missing API key. Provide an Authorization: Bearer header.",type:"invalid_request_error",param:null,code:"missing_api_key"}};return json(401,payload,{"WWW-Authenticate":'Bearer realm="lumen"'})};var methodNotAllowed=allow=>new Response(JSON.stringify({error:{message:`Method not allowed. This endpoint accepts ${allow}.`,type:"invalid_request_error",param:null,code:"method_not_allowed"}}),{status:405,headers:{...JSON_HEADERS,Allow:allow}});var MODELS={object:"list",data:[{id:"lumen-1-mini",object:"model",created:1745366400,owned_by:"lumen-labs"},{id:"lumen-1-pro",object:"model",created:1748304e3,owned_by:"lumen-labs"},{id:"lumen-embed-2",object:"model",created:1751241600,owned_by:"lumen-labs"}]};var handleApi=(request,url)=>{const path=url.pathname.length>1?url.pathname.replace(/\/+$/,"")||"/":url.pathname;const method=request.method;const isRead=method==="GET"||method==="HEAD";if(path==="/health"){if(!isRead)return methodNotAllowed("GET, HEAD");return json(200,{status:"ok",service:"lumen-edge",version:"3.4.1",region:"auto",timestamp:new Date().toISOString()})}if(path==="/api/v1/models"){if(!isRead)return methodNotAllowed("GET, HEAD");return json(200,MODELS)}if(path==="/api/v1/chat"||path.startsWith("/api/v1/chat/")){if(method!=="POST")return methodNotAllowed("POST");return authFailure(request)}if(path==="/api/v2beta/events"){if(!isRead)return methodNotAllowed("GET, HEAD");return authFailure(request)}if(path==="/telemetry/ingest"){if(method!=="POST")return methodNotAllowed("POST");return authFailure(request)}if(path==="/push/gateway"){if(!isRead)return methodNotAllowed("GET, HEAD");return authFailure(request)}if(path.startsWith("/api/")||path.startsWith("/telemetry/")||path.startsWith("/push/")){return json(404,{error:{message:`Unknown endpoint: ${method} ${path}`,type:"invalid_request_error",param:null,code:"not_found"}})}return null};var panel_default=`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SuperEdge \u63A7\u5236\u53F0</title>
<meta name="robots" content="noindex,nofollow">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<script>
(function () {
  try {
    var pref = localStorage.getItem('se.theme');
    var sys = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (pref === 'dark' || (pref !== 'light' && sys)) document.documentElement.classList.add('theme-dark');
  } catch (e) {}
})();
</script>
<!-- __PANEL2_STYLE__ -->
</head>
<body>
<div class="backdrop" aria-hidden="true"></div>

<header class="topbar">
  <div class="brand">
    <span class="mark" aria-hidden="true"></span>
    <span class="brand-name">SuperEdge <i>\u91D1\u4E1D\u96C0</i></span>
    <span class="chip">\u63A7\u5236\u53F0</span>
  </div>
  <div class="top-actions">
    <button type="button" id="theme-btn" class="ghost small" aria-label="\u5F53\u524D\u4E3B\u9898\uFF1A\u81EA\u52A8\uFF0C\u70B9\u51FB\u5207\u6362" title="\u5207\u6362\u4E3B\u9898\uFF08\u81EA\u52A8 / \u660E\u4EAE / \u6697\u8272\uFF09">\u81EA\u52A8</button>
    <span id="top-state" class="pill" hidden>\u5DF2\u9501\u5B9A</span>
    <button type="button" id="lock-btn" class="ghost small" hidden>\u9501\u5B9A</button>
  </div>
</header>

<main class="shell">
  <section id="app">
    <div class="workspace">

      <nav class="rail" aria-label="\u63A7\u5236\u53F0\u5206\u533A">
        <p class="rail-title">\u914D\u7F6E\u6D41\u7A0B</p>
        <a class="rail-item is-active" href="#sec-id"><span class="idx">01</span><span class="txt">\u8EAB\u4EFD\u6982\u89C8</span></a>
        <a class="rail-item" href="#sec-access"><span class="idx">02</span><span class="txt">\u51FA\u7AD9\u65B9\u5F0F</span></a>
        <a class="rail-item" href="#sec-node"><span class="idx">03</span><span class="txt">\u8282\u70B9\u6807\u8BC6</span></a>
        <a class="rail-item" href="#sec-transport"><span class="idx">04</span><span class="txt">\u4F20\u8F93\u6863\u4F4D</span></a>
        <div class="rail-foot">
          <span class="rail-ver">v1.9.3</span>
          <span>\u670D\u52A1\u7AEF\u6821\u9A8C</span>
        </div>
      </nav>

      <div class="stack">

        <section class="block" id="sec-id" aria-labelledby="h-id">
          <header class="block-head">
            <div>
              <span class="idx-line">01 / \u8EAB\u4EFD\u6982\u89C8</span>
              <h2 id="h-id">\u5F53\u524D\u8282\u70B9\u8EAB\u4EFD</h2>
            </div>
            <span class="tag ok">\u5DF2\u89E3\u9501</span>
          </header>
          <div class="facts">
            <div class="fact wide">
              <span class="k">\u8282\u70B9UUID</span>
              <code id="id-uuid"></code>
              <button type="button" id="id-eye" class="mini" aria-label="\u663E\u793A\u8282\u70B9UUID">\u663E\u793A</button>
              <button type="button" id="cp-uuid" class="mini">\u590D\u5236</button>
            </div>
            <div class="fact">
              <span class="k">\u5F53\u524D Host</span>
              <code id="id-host"></code>
            </div>
            <div class="fact">
              <span class="k">\u5B9E\u9645\u51FA\u53E3</span>
              <code id="id-server">\u672A\u751F\u6210</code>
            </div>
          </div>
        </section>

        <section class="block" id="sec-access" aria-labelledby="h-access">
          <header class="block-head">
            <div>
              <span class="idx-line">02 / \u51FA\u7AD9\u65B9\u5F0F</span>
              <h2 id="h-access">\u9009\u62E9\u51FA\u7AD9\u65B9\u5F0F</h2>
            </div>
            <span class="tag">\u5355\u9009</span>
          </header>

          <p class="sub-label">\u51FA\u7AD9\u65B9\u5F0F</p>
          <div class="picker" id="ptype-group" role="radiogroup" aria-labelledby="h-access">
            <label class="opt"><input type="radio" name="ptype" value="direct" checked><span class="opt-body"><b>\u7EAF\u76F4\u8FDE</b><em>\u63A8\u8350 \xB7 \u65E0\u4E2D\u8F6C</em></span></label>
            <label class="opt"><input type="radio" name="ptype" value="ip"><span class="opt-body"><b>proxyip \u4E2D\u8F6C</b><em>\u7B2C\u4E09\u65B9\u515C\u5E95</em></span></label>
            <label class="opt"><input type="radio" name="ptype" value="s5"><span class="opt-body"><b>SOCKS5 \u5907\u7528</b><em>\u76F4\u8FDE\u5931\u8D25\u65F6</em></span></label>
            <label class="opt"><input type="radio" name="ptype" value="h"><span class="opt-body"><b>HTTP \u5907\u7528</b><em>\u76F4\u8FDE\u5931\u8D25\u65F6</em></span></label>
            <label class="opt"><input type="radio" name="ptype" value="g5"><span class="opt-body"><b>SOCKS5 \u5168\u5C40</b><em>\u5168\u90E8\u8D70\u4EE3\u7406</em></span></label>
            <label class="opt"><input type="radio" name="ptype" value="gh"><span class="opt-body"><b>HTTP \u5168\u5C40</b><em>\u56FA\u5B9A\u51FA\u53E3</em></span></label>
          </div>

          <div id="ptype-hint" class="hint-box"></div>

          <div id="f-ip" class="collapse">
            <div class="field">
              <label for="ip-host">proxyip \u5730\u5740</label>
              <input id="ip-host" type="text" placeholder="1.2.3.4:443">
              <p class="help">\u76F4\u8FDE\u5931\u8D25\u65F6\u542F\u7528\u7684\u7B2C\u4E09\u65B9\u4E2D\u8F6C\u8282\u70B9\uFF0C\u7F3A\u7701\u7AEF\u53E3\u6309 443 \u5904\u7406\u3002</p>
            </div>
          </div>

          <div id="f-proxy" class="collapse">
            <div class="sub-head">\u4EE3\u7406\u51ED\u636E</div>
            <div class="field">
              <label for="pr-link">\u7C98\u8D34\u4EE3\u7406\u94FE\u63A5\uFF08\u53EF\u9009\uFF09</label>
              <input id="pr-link" type="text" placeholder="socks5://user:pass@host:port">
              <p class="help">\u7C98\u8D34\u5B8C\u6574\u94FE\u63A5\u4F1A\u81EA\u52A8\u8BC6\u522B\u534F\u8BAE\u5E76\u586B\u5145\u4E0B\u5217\u5B57\u6BB5\u3002</p>
            </div>
            <div class="row">
              <div class="field grow">
                <label for="pr-host">\u4EE3\u7406\u5730\u5740</label>
                <input id="pr-host" type="text" placeholder="host:port">
              </div>
              <div class="field">
                <label for="pr-user">\u7528\u6237\u540D</label>
                <input id="pr-user" type="text" placeholder="\u53EF\u9009">
              </div>
              <div class="field">
                <label for="pr-pass">\u5BC6\u7801</label>
                <input id="pr-pass" type="text" placeholder="\u53EF\u9009">
              </div>
            </div>
          </div>
        </section>

        <section class="block" id="sec-node" aria-labelledby="h-node">
          <header class="block-head">
            <div>
              <span class="idx-line">03 / \u8282\u70B9\u6807\u8BC6</span>
              <h2 id="h-node">\u5BA2\u6237\u7AEF\u91CC\u663E\u793A\u7684\u540D\u79F0\u4E0E\u5730\u5740</h2>
            </div>
          </header>
          <div class="field">
            <label for="nm">\u8282\u70B9\u540D\u79F0</label>
            <input id="nm" type="text" value="SuperEdge\u91D1\u4E1D\u96C0">
            <p class="help">\u5199\u5165\u5206\u4EAB\u94FE\u63A5\u7684\u5907\u6CE8\u6BB5\uFF0C\u51B3\u5B9A\u5BA2\u6237\u7AEF\u8282\u70B9\u5217\u8868\u91CC\u7684\u663E\u793A\u540D\u3002</p>
          </div>
          <div class="row">
            <div class="field grow">
              <label for="sv-addr">\u81EA\u5B9A\u4E49\u670D\u52A1\u5668</label>
              <input id="sv-addr" type="text" placeholder="\u7559\u7A7A\u7528\u5F53\u524D\u57DF\u540D">
            </div>
            <div class="field narrow">
              <label for="sv-port">\u7AEF\u53E3</label>
              <input id="sv-port" type="text" inputmode="numeric" placeholder="443">
            </div>
          </div>
          <p class="help">\u53EF\u586B\u4F18\u9009 IP \u6216\u81EA\u5B9A\u4E49\u57DF\u540D\uFF0C\u7559\u7A7A\u5219\u4F7F\u7528\u5F53\u524D\u57DF\u540D\u3002CF \u4EC5\u652F\u6301 443 / 2053 / 2083 / 2087 / 2096 / 8443\u3002</p>
          <div id="sv-err" class="err"></div>
        </section>

        <section class="block" id="sec-transport" aria-labelledby="h-transport">
          <header class="block-head">
            <div>
              <span class="idx-line">04 / \u4F20\u8F93\u6863\u4F4D</span>
              <h2 id="h-transport">\u4F20\u8F93\u6863\u4F4D\u4E0E\u63A5\u5165\u8DEF\u5F84</h2>
            </div>
          </header>

          <div class="field">
            <label id="ll-label">\u4F20\u8F93\u6863\u4F4D</label>
            <div class="picker three" role="radiogroup" aria-labelledby="ll-label">
              <label class="opt"><input type="radio" name="ll" value="0" checked><span class="opt-body"><b>\u5747\u8861</b><em>ll=0 \xB7 \u9ED8\u8BA4</em></span></label>
              <label class="opt"><input type="radio" name="ll" value="1"><span class="opt-body"><b>\u4F4E\u5EF6\u8FDF</b><em>ll=1</em></span></label>
              <label class="opt"><input type="radio" name="ll" value="2"><span class="opt-body"><b>\u9AD8\u901F\u4E0B\u8F7D</b><em>ll=2</em></span></label>
            </div>
            <div id="ll-hint" class="hint-box"></div>
            <div id="ll-table" class="ll-table" hidden></div>
          </div>

          <div class="field">
            <label>\u63A5\u5165\u8DEF\u5F84</label>
            <div class="picker two path-group" id="path-group" role="radiogroup" aria-label="\u63A5\u5165\u8DEF\u5F84">
              __PATH_OPTIONS__
            </div>
            <p class="help">\u9700\u4E0E\u5BA2\u6237\u7AEF WebSocket Path \u5B8C\u5168\u4E00\u81F4\uFF1B\u67D0\u6761\u8DEF\u5F84\u88AB\u5C01\u65F6\u53EF\u5207\u6362\u5176\u4F59\u8DEF\u5F84\u3002</p>
          </div>
        </section>

        <div class="actionbar">
          <div class="actionbar-info">
            <span id="action-state" class="tag ok">\u5DF2\u751F\u6210</span>
            <span class="actionbar-text">\u4FEE\u6539\u4EFB\u610F\u53C2\u6570\u540E\u9700\u91CD\u65B0\u751F\u6210</span>
          </div>
          <div class="actionbar-btns">
            <button type="button" id="reset-btn" class="ghost">\u91CD\u7F6E</button>
            <button type="button" id="gen-btn" class="primary">\u751F\u6210\u94FE\u63A5</button>
          </div>
        </div>

      </div>

      <aside class="output" aria-labelledby="h-out">
        <header class="output-head">
          <div>
            <span class="idx-line">\u8F93\u51FA</span>
            <h2 id="h-out">\u751F\u6210\u7ED3\u679C</h2>
          </div>
          <span id="state" class="tag ok">\u5DF2\u751F\u6210</span>
        </header>

        <div class="summary">
          <span><i>\u51FA\u7AD9</i><b id="sum-ptype">\u7EAF\u76F4\u8FDE</b></span>
          <span><i>\u4F20\u8F93</i><b id="sum-ll">\u5747\u8861</b></span>
          <span><i>\u8DEF\u5F84</i><b id="sum-path">\u2014</b></span>
        </div>

        <div class="field">
          <label for="out-vless">VLESS \u94FE\u63A5</label>
          <div class="out-row">
            <input id="out-vless" type="text" readonly>
            <button type="button" id="cp-vless" class="mini">\u590D\u5236</button>
          </div>
        </div>

        <div class="field">
          <label for="out-path">Path \xB7 \u624B\u52A8\u586B\u5199\u65F6\u4F7F\u7528</label>
          <div class="out-row">
            <input id="out-path" type="text" readonly>
            <button type="button" id="cp-path" class="mini">\u590D\u5236</button>
          </div>
        </div>

        <div class="qr-box">
          <img id="qr-img" alt="\u8282\u70B9\u4E8C\u7EF4\u7801" width="320" height="320" hidden>
          <div id="qr-tip" class="qr-tip" aria-live="polite">\u4E8C\u7EF4\u7801\u6309\u9700\u751F\u6210\uFF0C\u51CF\u5C11\u5916\u90E8\u8BF7\u6C42</div>
          <button type="button" id="qr-gen" class="ghost small">\u751F\u6210\u4E8C\u7EF4\u7801</button>
        </div>

        <div class="usage">\u7535\u8111\u7AEF\u5BFC\u5165 VLESS \u94FE\u63A5\uFF1B\u624B\u673A\u7AEF\u626B\u7801\u5BFC\u5165\u3002\u4E8C\u7EF4\u7801\u6BCF\u70B9\u51FB\u4E00\u6B21\u751F\u6210\uFF0C\u4F1A\u628A\u542B\u8282\u70B9UUID \u7684\u94FE\u63A5\u53D1\u9001\u7ED9 qr.tgds.eu.org\u3002</div>
        <div class="warn">\u6B64\u9875\u9762\u5305\u542B\u8282\u70B9UUID\uFF0C\u8BF7\u52FF\u622A\u56FE\u6216\u5206\u4EAB\u94FE\u63A5</div>
      </aside>

    </div>

    <footer class="foot">
      <span>SuperEdge \u91D1\u4E1D\u96C0 \xB7 \u79C1\u6709\u63A7\u5236\u53F0</span>
      <span>\u4F1A\u8BDD\u7531\u670D\u52A1\u7AEF\u6821\u9A8C \xB7 v1.9.3</span>
    </footer>
  </section>
</main>

<div id="qr-zoom" class="qr-zoom" aria-hidden="true"><img alt="\u4E8C\u7EF4\u7801\u653E\u5927"></div>

<!-- __PANEL2_DATA__ -->
<!-- __PANEL2_SCRIPT__ -->
</body>
</html>`;var panel_default2='*{box-sizing:border-box}\n[hidden]{display:none!important}\n:root{\n  color-scheme:light;\n  --bg:#eef1f8;\n  --card:#ffffff;\n  --card-2:#f6f8fd;\n  --ink:#0d1522;\n  --muted:#54637d;\n  --faint:#6b7b93;\n  --line:#e2e8f2;\n  --line-2:#ccd6e5;\n  --accent:#4f46e5;\n  --accent-h:#4338ca;\n  --accent-soft:#eef0ff;\n  --ok:#136c36;\n  --ok-soft:#e6f6ec;\n  --warn:#a2560a;\n  --warn-soft:#fdf2e2;\n  --danger:#b91c1c;\n  --radius:16px;\n  --radius-sm:9px;\n  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;\n  --shadow:0 18px 40px -30px rgba(13,21,34,.42),0 1px 2px rgba(13,21,34,.05);\n  --ring:0 0 0 3px rgba(79,70,229,.16);\n  --topbar:rgba(255,255,255,.84);\n  --rail:240px;\n  --out:380px;\n}\nhtml.theme-dark{\n  color-scheme:dark;\n  --bg:#080d16;\n  --card:#101826;\n  --card-2:#0c1420;\n  --ink:#e8eef8;\n  --muted:#9aa8bd;\n  --faint:#7b8ca4;\n  --line:#1b2739;\n  --line-2:#29384f;\n  --accent:#7c7cf5;\n  --accent-h:#9595ff;\n  --accent-soft:#171a38;\n  --ok:#6ee7a0;\n  --ok-soft:#10241a;\n  --warn:#fbc46a;\n  --warn-soft:#291f10;\n  --danger:#f87171;\n  --shadow:0 22px 46px -30px rgba(0,0,0,.85),0 1px 3px rgba(0,0,0,.4);\n  --ring:0 0 0 3px rgba(124,124,245,.24);\n  --topbar:rgba(8,13,22,.8);\n}\nhtml,body{min-height:100%}\nhtml{scroll-behavior:smooth}\nbody{\n  margin:0;background:var(--bg);color:var(--ink);\n  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;\n  font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased;\n}\n.backdrop{\n  position:fixed;inset:0;z-index:-1;\n  background:\n    radial-gradient(900px 480px at 6% -10%,rgba(79,70,229,.15),transparent 60%),\n    radial-gradient(720px 420px at 98% 0%,rgba(14,165,233,.12),transparent 62%),\n    var(--bg);\n}\n.topbar{\n  position:sticky;top:0;z-index:30;\n  display:flex;align-items:center;justify-content:space-between;gap:16px;\n  height:60px;padding:0 26px;\n  background:var(--topbar);border-bottom:1px solid var(--line);\n  backdrop-filter:saturate(160%) blur(14px);\n}\n.brand{display:flex;align-items:center;gap:10px;min-width:0}\n.mark{\n  width:24px;height:24px;border-radius:8px;flex:0 0 auto;\n  background:linear-gradient(145deg,var(--accent),#22d3ee);\n  box-shadow:inset 0 0 0 1px rgba(255,255,255,.22);\n}\n.brand-name{font-size:14px;font-weight:650;letter-spacing:.1px;white-space:nowrap}\n.brand-name i{font-style:normal;font-weight:500;color:var(--muted)}\n.chip{\n  padding:2px 8px;border-radius:999px;font-size:11px;color:var(--accent);\n  background:var(--accent-soft);border:1px solid rgba(79,70,229,.18);white-space:nowrap;\n}\n.top-actions{display:flex;align-items:center;gap:10px}\n.shell{max-width:1320px;margin:0 auto;padding:24px 24px 56px}\n\n/* \u4E09\u680F\u5DE5\u4F5C\u533A */\n.workspace{display:grid;grid-template-columns:var(--rail) minmax(0,1fr) var(--out);gap:22px;align-items:start}\n.rail{position:sticky;top:84px;display:flex;flex-direction:column;gap:2px;padding:14px 10px}\n.rail-title{margin:0 0 8px;padding:0 12px;font-size:11px;letter-spacing:1.2px;color:var(--faint);font-weight:600}\n.rail-item{\n  display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:10px;\n  color:var(--muted);text-decoration:none;transition:background .15s,color .15s;\n}\n.rail-item .idx{font-family:var(--mono);font-size:11px;color:var(--faint)}\n.rail-item .txt{font-size:13.5px;font-weight:550}\n.rail-item:hover{background:var(--card);color:var(--ink)}\n.rail-item.is-active{background:var(--card);color:var(--accent);box-shadow:var(--shadow)}\n.rail-item.is-active .idx{color:var(--accent)}\n.rail-foot{\n  margin-top:14px;padding:12px 12px 0;border-top:1px solid var(--line);\n  display:flex;justify-content:space-between;font-size:11px;color:var(--faint);\n}\n.rail-ver{font-family:var(--mono)}\n.stack{display:flex;flex-direction:column;gap:18px;min-width:0}\n.block{\n  padding:22px 22px 20px;background:var(--card);border:1px solid var(--line);\n  border-radius:var(--radius);box-shadow:var(--shadow);scroll-margin-top:76px;\n}\n.block-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:16px}\n.idx-line{display:block;font-family:var(--mono);font-size:11px;letter-spacing:.6px;color:var(--accent);margin-bottom:4px}\n.block-head h2,.output-head h2{margin:0;font-size:16px;letter-spacing:-.2px;line-height:1.35}\n.tag{\n  flex:0 0 auto;padding:3px 9px;border-radius:999px;font-size:11px;font-weight:600;\n  color:var(--muted);background:var(--card-2);border:1px solid var(--line);\n}\n.tag.ok{color:var(--ok);background:var(--ok-soft);border-color:transparent}\n.tag.stale{color:var(--warn);background:var(--warn-soft);border-color:transparent}\n.pill{\n  padding:3px 10px;border-radius:999px;font-size:11px;font-weight:600;\n  color:var(--muted);background:var(--card-2);border:1px solid var(--line);\n}\n.pill.ok{color:var(--ok);background:var(--ok-soft);border-color:transparent}\n.pill.stale{color:var(--warn);background:var(--warn-soft);border-color:transparent}\n/* \u8868\u5355 */\n.field{display:flex;flex-direction:column;gap:6px;margin-bottom:14px;min-width:0}\n.field>label,#ll-label{font-size:12.5px;font-weight:600;color:var(--muted);letter-spacing:.2px}\ninput[type=text]{\n  width:100%;height:40px;padding:0 12px;\n  border:1px solid var(--line-2);border-radius:var(--radius-sm);\n  background:var(--card-2);color:var(--ink);\n  font-family:var(--mono);font-size:13px;outline:none;\n  transition:border-color .15s,background .15s,box-shadow .15s;\n}\ninput::placeholder{color:var(--faint);font-family:inherit}\ninput[type=text]:focus{\n  border-color:var(--accent);background:var(--card);box-shadow:var(--ring);\n}\ninput[readonly]{cursor:text}\n.help{margin:0;font-size:12px;line-height:1.6;color:var(--faint)}\n.row{display:flex;gap:12px;align-items:flex-start}\n.row>.field{flex:1;min-width:0}\n.row>.field.narrow{flex:0 0 104px}\n.row>.field.grow{flex:1.5}\n.sub-head{\n  margin:4px 0 12px;padding-top:14px;border-top:1px dashed var(--line);\n  font-size:11.5px;letter-spacing:.8px;font-weight:600;color:var(--faint);\n}\n\n/* \u9009\u9879\u5361\u7247 */\n.sub-label{margin:0 0 8px;font-size:12.5px;font-weight:600;color:var(--muted)}\n.picker{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}\n.picker.two{grid-template-columns:repeat(2,minmax(0,1fr))}\n.opt{\n  position:relative;display:block;padding:11px 12px;cursor:pointer;\n  background:var(--card-2);border:1px solid var(--line-2);border-radius:12px;\n  transition:border-color .15s,background .15s,box-shadow .15s,transform .1s;\n}\n.opt:hover{border-color:var(--muted)}\n.opt input{position:absolute;width:0;height:0;opacity:0}\n.opt-body{display:flex;flex-direction:column;gap:2px;min-width:0}\n.opt-body b{font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n.opt-body em{font-style:normal;font-size:11px;color:var(--faint)}\n.opt.mono .opt-body b{font-family:var(--mono);font-size:12px;font-weight:500}\n.opt:has(input:checked){border-color:var(--accent);background:var(--accent-soft)}\n.opt:has(input:checked) b{color:var(--accent)}\n.opt:has(input:checked) em{color:var(--accent)}\n.opt:has(input:focus-visible){box-shadow:var(--ring)}\n.path-group .opt-body b{font-size:12px}\n\n.hint-box{\n  margin:2px 0 14px;padding:10px 12px;border-radius:10px;font-size:12.5px;line-height:1.6;\n  color:var(--muted);background:var(--card-2);border:1px dashed var(--line-2);\n}\n.hint-box.warn{color:var(--warn);background:var(--warn-soft);border-color:rgba(162,86,10,.28)}\n.ll-table{\n  display:grid;grid-template-columns:1fr auto;gap:6px 16px;\n  margin:0 0 14px;padding:10px 12px;\n  background:var(--card-2);border:1px solid var(--line);border-radius:10px;\n}\n.ll-row{display:contents}\n.ll-table span{font-size:12px;color:var(--faint)}\n.ll-table b{font-family:var(--mono);font-size:12px;font-weight:600;text-align:right}\n.collapse{display:none!important}\n.collapse.open{display:block!important;margin-top:6px}\n.err{min-height:16px;font-size:12px;color:var(--danger)}\n\n/* \u8EAB\u4EFD */\n.facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}\n.fact{\n  display:flex;align-items:center;gap:10px;min-width:0;padding:10px 12px;\n  background:var(--card-2);border:1px solid var(--line);border-radius:11px;\n}\n.fact.wide{grid-column:1/-1}\n.fact .k{flex:0 0 auto;font-size:11.5px;color:var(--faint)}\n.fact code{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono);font-size:12.5px}\n.fact .mini{height:28px;padding:0 9px;font-size:11px}\n\n/* \u6309\u94AE */\n.primary{\n  height:40px;padding:0 20px;border:0;border-radius:var(--radius-sm);\n  background:var(--accent);color:#fff;font-size:13.5px;font-weight:600;\n  cursor:pointer;transition:background .15s,transform .1s;\n}\n.primary:hover{background:var(--accent-h)}\n.primary:active{transform:translateY(1px)}\n.primary:disabled{opacity:.62;cursor:default;transform:none}\n#gen-btn.dirty{background:var(--warn)}\n#gen-btn.dirty:hover{background:#8a4a08}\n.ghost{\n  height:40px;padding:0 16px;border-radius:var(--radius-sm);\n  border:1px solid var(--line-2);background:transparent;color:var(--muted);\n  font-size:13px;cursor:pointer;transition:border-color .15s,color .15s;\n}\n.ghost:hover{border-color:var(--accent);color:var(--accent)}\n.ghost.small{height:30px;padding:0 11px;font-size:12px}\n.mini{\n  flex:0 0 auto;height:40px;padding:0 12px;border-radius:var(--radius-sm);\n  border:1px solid var(--line-2);background:var(--card);color:var(--muted);\n  font-size:12px;cursor:pointer;white-space:nowrap;\n}\n.mini:hover{border-color:var(--accent);color:var(--accent)}\n\n/* \u64CD\u4F5C\u680F */\n.actionbar{\n  position:sticky;bottom:10px;z-index:20;\n  display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;\n  padding:12px 16px;background:var(--card);border:1px solid var(--line);\n  border-radius:14px;box-shadow:0 12px 30px -18px rgba(13,21,34,.4);\n}\n.actionbar-info{display:flex;align-items:center;gap:10px;min-width:0}\n.actionbar-text{font-size:12px;color:var(--faint)}\n.actionbar-btns{display:flex;gap:10px;margin-left:auto}\n/* \u8F93\u51FA\u680F */\n.output{\n  position:sticky;top:84px;\n  display:flex;flex-direction:column;\n  padding:20px;background:var(--card);border:1px solid var(--line);\n  border-radius:var(--radius);box-shadow:var(--shadow);\n}\n.output-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:16px}\n.summary{\n  display:flex;flex-direction:column;gap:6px;margin-bottom:14px;padding:10px 12px;\n  background:var(--card-2);border:1px solid var(--line);border-radius:11px;\n}\n.summary span{display:flex;align-items:baseline;justify-content:space-between;gap:10px;min-width:0}\n.summary i{flex:0 0 auto;font-style:normal;font-size:11.5px;color:var(--faint)}\n.summary b{min-width:0;font-weight:600;font-family:var(--mono);font-size:11.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n.out-row{display:flex;gap:8px}\n.out-row input{flex:1;min-width:0}\n.qr-box{\n  margin:4px 0 12px;padding:16px;border-radius:12px;\n  background:var(--card-2);border:1px solid var(--line);\n  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;min-height:200px;\n}\n.qr-box img{width:196px;height:196px;border-radius:10px;background:#fff;padding:6px;cursor:zoom-in}\n.qr-tip{font-size:12px;color:var(--faint);text-align:center}\n.qr-tip.err{color:var(--danger)}\n.qr-box .ghost.small{min-width:132px}\n.usage{font-size:12px;line-height:1.65;color:var(--muted)}\n.warn{margin-top:12px;padding-top:12px;border-top:1px dashed var(--line);font-size:11.5px;color:var(--warn)}\n.foot{\n  display:flex;align-items:center;justify-content:space-between;gap:12px;\n  margin-top:18px;padding:0 4px;font-size:11.5px;color:var(--faint);\n}\n.qr-zoom{\n  position:fixed;inset:0;z-index:60;display:none;align-items:center;justify-content:center;\n  background:rgba(6,10,18,.72);backdrop-filter:blur(4px);padding:24px;cursor:zoom-out;\n}\n.qr-zoom.open{display:flex}\n.qr-zoom img{width:min(78vw,78vh);height:min(78vw,78vh);background:#fff;border-radius:16px;padding:12px}\n\n/* \u54CD\u5E94\u5F0F */\n@media (max-width:1180px){\n  .workspace{grid-template-columns:200px minmax(0,1fr)}\n  .output{position:static;grid-column:1/-1}\n  .output .qr-box{min-height:180px}\n}\n@media (max-width:900px){\n  .workspace{grid-template-columns:1fr;gap:16px}\n  .rail{\n    position:sticky;top:60px;z-index:25;flex-direction:row;gap:6px;overflow-x:auto;\n    padding:12px 2px;background:var(--topbar);border-bottom:1px solid var(--line);\n    backdrop-filter:saturate(160%) blur(12px);-webkit-overflow-scrolling:touch;\n  }\n  .rail-title,.rail-foot{display:none}\n  .rail-item{flex:0 0 auto;padding:7px 12px;border:1px solid var(--line-2);border-radius:999px}\n  .rail-item.is-active{box-shadow:none}\n  .rail-item .txt{font-size:12.5px}\n  .actionbar{bottom:8px}\n}\n@media (max-width:600px){\n  .topbar{height:56px;padding:0 14px}\n  .topbar .chip{display:none}\n  #theme-btn{padding:0 9px}\n  .brand-name{font-size:13px}\n  .shell{padding:14px 12px 40px}\n  .block,.output{padding:18px 16px}\n  .picker,.picker.two{grid-template-columns:repeat(2,minmax(0,1fr))}\n  .picker.three{grid-template-columns:1fr}\n  .facts{grid-template-columns:1fr}\n  input[type=text]{font-size:16px;height:44px}\n  .row{flex-wrap:wrap}\n  .row>.field{flex:1 1 100%}\n  .row>.field.narrow{flex:0 0 104px}\n  .actionbar{padding:10px 12px;gap:10px}\n  .actionbar-text{display:none}\n  .actionbar-btns{flex:1;margin-left:0}\n  .actionbar-btns .primary{flex:1}\n  .out-row{flex-wrap:wrap}\n  .out-row .mini{width:100%;height:38px}\n  .foot{flex-direction:column;align-items:flex-start;gap:4px}\n}\n@media (prefers-reduced-motion:reduce){\n  *{transition:none!important;animation:none!important}\n}';var panel_default3=`(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  /* \u8282\u70B9UUID \u53EA\u5728\u4F1A\u8BDD\u6821\u9A8C\u901A\u8FC7\u540E\u7531\u670D\u52A1\u7AEF\u6CE8\u5165\uFF0C\u8FD9\u91CC\u4E0D\u505A\u4E8C\u6B21\u89E3\u5BC6 */
  var uuid = window.NODE_ID || '';
  var locking = false;
  var dirty = false;
  var qrUrl = '';
  var qrSeq = 0;
  var qrLink = '';
  var copyTimers = {};
  var idShown = false;
  var idTimer = 0;
  var themeMode = 'system';
  var lastAct = Date.now();
  var IDLE_MS = 15 * 60 * 1000;
  var THEME_KEY = 'se.theme';
  var mql = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

  var PTYPE_HINT = {
    direct: '\u7EAF\u76F4\u8FDE\uFF1A\u4E0D\u505A\u4EFB\u4F55\u4E2D\u8F6C\uFF0C\u51FA\u53E3\u5373 Cloudflare \u8282\u70B9\u672C\u8EAB\u3002\u901F\u5EA6\u6700\u597D\uFF1B\u76EE\u6807 IP \u88AB\u5899\u65F6\u65E0\u6CD5\u8BBF\u95EE\u3002',
    ip: 'proxyip \u4E2D\u8F6C\uFF1A\u76F4\u8FDE\u5931\u8D25\u65F6\u7ECF\u7B2C\u4E09\u65B9\u8282\u70B9\u8F6C\u53D1\u3002\u4F9D\u8D56\u7B2C\u4E09\u65B9\u8D28\u91CF\uFF0C\u65E0\u53EF\u7528\u6027\u4FDD\u8BC1\u3002',
    s5: 'SOCKS5 \u5907\u7528\uFF1A\u4EC5\u5F53\u76F4\u8FDE\u5931\u8D25\u65F6\u542F\u7528\u4F60\u7684 SOCKS5\uFF0C\u989D\u5916\u5F00\u9500\u5C0F\uFF0C\u53EF\u7528\u6027\u53D6\u51B3\u4E8E\u81EA\u5EFA\u4EE3\u7406\u3002',
    h: 'HTTP \u5907\u7528\uFF1A\u4EC5\u5F53\u76F4\u8FDE\u5931\u8D25\u65F6\u542F\u7528\u4F60\u7684 HTTP \u4EE3\u7406\uFF0C\u9002\u5408\u5DF2\u6709 HTTP \u51FA\u53E3\u7684\u573A\u666F\u3002',
    g5: 'SOCKS5 \u5168\u5C40\uFF1A\u6240\u6709\u51FA\u7AD9\u90FD\u8D70 SOCKS5\u3002\u9690\u85CF\u771F\u5B9E\u51FA\u53E3\uFF0C\u901F\u5EA6\u4E0E\u7A33\u5B9A\u6027\u5B8C\u5168\u53D6\u51B3\u4E8E\u8BE5\u4EE3\u7406\u3002',
    gh: 'HTTP \u5168\u5C40\uFF1A\u6240\u6709\u51FA\u7AD9\u90FD\u8D70 HTTP \u4EE3\u7406\uFF0C\u9002\u5408\u5F3A\u5236\u56FA\u5B9A\u51FA\u53E3\u7684\u573A\u666F\u3002'
  };

  /* \u573A\u666F\u8BF4\u660E\u53EA\u63CF\u8FF0\u7528\u9014\uFF0C\u4E0D\u5199\u4EFB\u4F55\u6570\u503C\uFF1B
   * \u5177\u4F53\u53C2\u6570\u4E00\u5F8B\u7531\u670D\u52A1\u7AEF\u4E0B\u53D1\u7684 LL_PROFILES \u6E32\u67D3\uFF0C\u907F\u514D\u4E0E PROFILES \u8C03\u6574\u540E\u5931\u771F\u3002 */
  var LL_SCENE = {
    '0': '\u5747\u8861\uFF1A\u9002\u5408\u65E5\u5E38\u7F51\u9875\u4E0E\u7EFC\u5408\u573A\u666F\uFF0C\u517C\u987E\u5EF6\u8FDF\u4E0E\u541E\u5410\u3002',
    '1': '\u4F4E\u5EF6\u8FDF\uFF1A\u4EA4\u4E92\u4F18\u5148\uFF0C\u9002\u5408 SSH\u3001\u6E38\u620F\u3001\u8FDC\u7A0B\u684C\u9762\u4E0E\u5B9E\u65F6\u901A\u4FE1\u3002',
    '2': '\u9AD8\u901F\u4E0B\u8F7D\uFF1A\u541E\u5410\u4F18\u5148\uFF0C\u9002\u5408\u5E94\u7528\u5546\u5E97\u4E0E\u7F51\u76D8\u5927\u6587\u4EF6\u3002'
  };

  var LL_ROWS = [
    ['\u4E0B\u884C\u5408\u5E76', 'dnPack', 'byte'],
    ['\u4E0A\u884C\u5408\u5E76', 'upPack', 'byte'],
    ['\u5355\u6B21\u8BFB\u53D6', 'chunk', 'byte'],
    ['\u5907\u7528\u5207\u6362', 'stagger', 'ms'],
    ['\u5EFA\u8FDE\u8D85\u65F6', 'totalTimeout', 'ms'],
    ['\u80CC\u538B\u7F13\u51B2', 'dnHigh', 'byte']
  ];

  function maskId(s) {
    if (!s) return '';
    return s.slice(0, 4) + ' **** ' + s.slice(-4);
  }

  function renderId() {
    $('id-uuid').textContent = idShown ? uuid : maskId(uuid);
    var btn = $('id-eye');
    btn.textContent = idShown ? '\u9690\u85CF' : '\u663E\u793A';
    btn.setAttribute('aria-label', (idShown ? '\u9690\u85CF' : '\u663E\u793A') + '\u8282\u70B9UUID');
  }

  function toggleId() {
    idShown = !idShown;
    clearTimeout(idTimer);
    if (idShown) {
      idTimer = setTimeout(function () { idShown = false; renderId(); }, 10000);
    }
    renderId();
  }

  function readTheme() {
    try {
      var v = localStorage.getItem(THEME_KEY);
      themeMode = v === 'light' || v === 'dark' ? v : 'system';
    } catch (e) { themeMode = 'system'; }
  }

  function applyTheme() {
    var dark = themeMode === 'dark' || (themeMode === 'system' && mql && mql.matches);
    document.documentElement.classList.toggle('theme-dark', !!dark);
    var btn = $('theme-btn');
    if (!btn) return;
    btn.textContent = themeMode === 'dark' ? '\u6697\u8272' : themeMode === 'light' ? '\u660E\u4EAE' : '\u81EA\u52A8';
    btn.setAttribute('aria-label', '\u5F53\u524D\u4E3B\u9898\uFF1A' + btn.textContent + '\uFF0C\u70B9\u51FB\u5207\u6362');
  }

  function cycleTheme() {
    themeMode = themeMode === 'system' ? 'light' : themeMode === 'light' ? 'dark' : 'system';
    try {
      if (themeMode === 'system') localStorage.removeItem(THEME_KEY);
      else localStorage.setItem(THEME_KEY, themeMode);
    } catch (e) {}
    applyTheme();
  }

  function initIdle() {
    ['pointerdown', 'keydown', 'input'].forEach(function (ev) {
      document.addEventListener(ev, function () { lastAct = Date.now(); }, { passive: true });
    });
    setInterval(function () {
      if (Date.now() - lastAct >= IDLE_MS) lock();
    }, 30000);
  }

  function trimNum(n) {
    return String(+n.toFixed(2));
  }

  function fmtBytes(n) {
    if (typeof n !== 'number') return '\u2014';
    if (n >= 1024 * 1024) return trimNum(n / (1024 * 1024)) + ' MB';
    if (n >= 1024) return trimNum(n / 1024) + ' KB';
    return n + ' B';
  }

  function fmtMs(n) {
    if (typeof n !== 'number') return '\u2014';
    return n >= 1000 ? trimNum(n / 1000) + ' s' : n + ' ms';
  }

  function showApp() {
    $('lock-btn').hidden = false;
    $('top-state').hidden = false;
    $('id-host').textContent = location.host || '\u672A\u77E5';
    idShown = false;
    clearTimeout(idTimer);
    renderId();
    lastAct = Date.now();
    uf();
    ph();
    renderLL();
    generate();
    var first = document.querySelector('input[name="ptype"]:checked');
    if (first) first.focus();
  }

  /* \u9501\u5B9A = \u6CE8\u9500\u670D\u52A1\u7AEF\u4F1A\u8BDD\uFF0C\u7136\u540E\u56DE\u5230\u901A\u7528\u767B\u5F55\u9875\uFF1B\u672A\u751F\u6210\u7684\u53C2\u6570\u4F1A\u968F\u9875\u9762\u5237\u65B0\u4E22\u5F03 */
  function lock() {
    if (locking) return;
    locking = true;
    fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' }).then(
      function () { location.replace(location.href); },
      function () { location.replace(location.href); }
    );
  }

  function llv() {
    var el = document.querySelector('input[name="ll"]:checked');
    return el ? el.value : '0';
  }

  function setLL(v) {
    document.querySelectorAll('input[name="ll"]').forEach(function (el) {
      el.checked = el.value === v;
    });
  }

  function ptypeVal() {
    var el = document.querySelector('input[name="ptype"]:checked');
    return el ? el.value : 'direct';
  }

  function setPtype(v) {
    document.querySelectorAll('input[name="ptype"]').forEach(function (el) {
      el.checked = el.value === v;
    });
  }

  function pathVal() {
    var el = document.querySelector('input[name="path"]:checked');
    return el ? el.value : '';
  }

  function setPath(v) {
    var list = document.querySelectorAll('input[name="path"]');
    if (!list.length) return;
    var hit = false;
    list.forEach(function (el) {
      el.checked = el.value === v;
      if (el.checked) hit = true;
    });
    if (!hit) list[0].checked = true;
  }

  function uf() {
    var t = ptypeVal();
    $('f-ip').classList.toggle('open', t === 'ip');
    $('f-proxy').classList.toggle('open', t === 's5' || t === 'h' || t === 'g5' || t === 'gh');
  }

  function ph() {
    $('ptype-hint').textContent = PTYPE_HINT[ptypeVal()] || '';
  }

  function renderLL() {
    var v = llv();
    var box = $('ll-hint');
    box.textContent = LL_SCENE[v] || '';
    box.classList.toggle('warn', v !== '0');

    var table = $('ll-table');
    var data = (window.LL_PROFILES || {})[v];
    if (!data) { table.hidden = true; table.innerHTML = ''; return; }
    var html = '';
    LL_ROWS.forEach(function (row) {
      var raw = data[row[1]];
      var val = row[2] === 'ms' ? fmtMs(raw) : fmtBytes(raw);
      html += '<div class="ll-row"><span>' + row[0] + '</span><b>' + val + '</b></div>';
    });
    table.innerHTML = html;
    table.hidden = false;
  }

  function buildPath() {
    var t = ptypeVal();
    var ps = ['ed=2560'];
    var ll = llv();
    if (ll !== '0') ps.push('ll=' + ll);

    if (t === 'ip') {
      var ip = $('ip-host').value.trim();
      if (ip) ps.push('ip=' + encodeURIComponent(ip));
    } else if (t === 's5' || t === 'h' || t === 'g5' || t === 'gh') {
      var host = $('pr-host').value.trim();
      if (host) {
        var scheme = (t === 's5' || t === 'g5') ? 'socks5://' : 'http://';
        var user = $('pr-user').value.trim();
        var pass = $('pr-pass').value.trim();
        var auth = user && pass ? user + ':' + pass + '@' : (user ? user + '@' : '');
        ps.push(t + '=' + encodeURIComponent(scheme + auth + host));
      }
    }
    return pathVal() + '?' + ps.join('&');
  }

  function server() {
    var err = $('sv-err');
    var addr = $('sv-addr').value.trim();
    var port = $('sv-port').value.trim();
    err.textContent = '';

    addr = addr.replace(/^[a-z][a-z0-9+.-]*:\\/\\//i, '').split(/[/?#]/)[0];
    var m = addr.match(/^(\\[[^\\]]+\\])(?::(\\d{1,5}))?$/);
    if (m) {
      addr = m[1];
      if (!port && m[2]) port = m[2];
    } else {
      m = addr.match(/^([^:\\[\\]]+):(\\d{1,5})$/);
      if (m) {
        addr = m[1];
        if (!port) port = m[2];
      }
    }
    if (!addr) addr = location.hostname || location.host;
    if ((addr.match(/:/g) || []).length > 1 && addr.charAt(0) !== '[') addr = '[' + addr + ']';
    if (!/^[A-Za-z0-9._\\[\\]:-]+$/.test(addr)) {
      err.textContent = '\u670D\u52A1\u5668\u5730\u5740\u683C\u5F0F\u4E0D\u6B63\u786E\uFF0C\u8BF7\u586B IP \u6216\u57DF\u540D\uFF08\u4E0D\u542B\u534F\u8BAE\u4E0E\u8DEF\u5F84\uFF09';
      return null;
    }
    if (!port) port = location.port || '443';
    if (!/^\\d{1,5}$/.test(port) || +port < 1 || +port > 65535) {
      err.textContent = '\u7AEF\u53E3\u9700\u4E3A 1-65535 \u7684\u6574\u6570';
      return null;
    }
    return { addr: addr, port: port };
  }

  function buildVless(path, target) {
    if (!uuid) return '';
    var host = location.host;
    var name = $('nm').value.trim() || 'SuperEdge\u91D1\u4E1D\u96C0';
    var q = 'encryption=none&security=tls&sni=' + encodeURIComponent(host) +
      '&type=ws&host=' + encodeURIComponent(host) +
      '&path=' + encodeURIComponent(path);
    return 'vless://' + uuid + '@' + target.addr + ':' + target.port + '?' + q + '#' + encodeURIComponent(name);
  }

  function generate() {
    var target = server();
    var path = buildPath();
    var link = target ? buildVless(path, target) : '';
    $('out-path').value = link ? path : '';
    $('out-vless').value = link;
    $('id-server').textContent = link ? target.addr + ':' + target.port : '\u672A\u751F\u6210';
    syncSummary(path);
    if (link !== qrLink) {
      var hadQR = !!qrLink;
      qrLink = '';
      clearQR(hadQR ? '\u53C2\u6570\u5DF2\u53D8\u66F4\uFF0C\u8BF7\u91CD\u65B0\u751F\u6210\u4E8C\u7EF4\u7801' : '\u4E8C\u7EF4\u7801\u6309\u9700\u751F\u6210\uFF0C\u51CF\u5C11\u5916\u90E8\u8BF7\u6C42', false);
    }
    setDirty(false);
  }

  function labelOf(name) {
    var el = document.querySelector('input[name="' + name + '"]:checked');
    var b = el && el.parentNode.querySelector('b');
    return b ? b.textContent : '\u2014';
  }

  function syncSummary(path) {
    $('sum-ptype').textContent = labelOf('ptype');
    $('sum-ll').textContent = labelOf('ll');
    $('sum-path').textContent = pathVal() || '\u2014';
    $('sum-path').title = path || '';
  }

  function clearQR(text, isErr) {
    qrSeq++;
    if (qrUrl) { URL.revokeObjectURL(qrUrl); qrUrl = ''; }
    var img = $('qr-img');
    img.hidden = true;
    img.removeAttribute('src');
    var tip = $('qr-tip');
    tip.className = 'qr-tip' + (isErr ? ' err' : '');
    tip.textContent = text;
    var btn = $('qr-gen');
    btn.disabled = false;
    btn.textContent = '\u751F\u6210\u4E8C\u7EF4\u7801';
  }

  function makeQR() {
    var link = $('out-vless').value;
    if (!link) {
      clearQR('\u94FE\u63A5\u672A\u751F\u6210\uFF0C\u65E0\u6CD5\u751F\u6210\u4E8C\u7EF4\u7801', true);
      return;
    }
    var seq = ++qrSeq;
    var btn = $('qr-gen');
    var tip = $('qr-tip');
    var img = $('qr-img');
    btn.disabled = true;
    btn.textContent = '\u751F\u6210\u4E2D\u2026';
    tip.className = 'qr-tip';
    tip.textContent = '\u6B63\u5728\u8BF7\u6C42\u4E8C\u7EF4\u7801\u670D\u52A1\u2026';
    img.hidden = true;

    fetch('https://qr.tgds.eu.org/api/qrcode?text=' + encodeURIComponent(link) + '&level=M&size=320&format=svg')
      .then(function (r) { if (!r.ok) throw new Error('qr'); return r.blob(); })
      .then(function (blob) {
        if (seq !== qrSeq) return;
        if (qrUrl) URL.revokeObjectURL(qrUrl);
        qrUrl = URL.createObjectURL(blob);
        img.src = qrUrl;
        img.hidden = false;
        qrLink = link;
        tip.textContent = '\u624B\u673A\u626B\u7801\u5BFC\u5165 \xB7 \u70B9\u51FB\u653E\u5927';
        btn.disabled = false;
        btn.textContent = '\u91CD\u65B0\u751F\u6210\u4E8C\u7EF4\u7801';
      })
      .catch(function () {
        if (seq !== qrSeq) return;
        clearQR('\u4E8C\u7EF4\u7801\u751F\u6210\u5931\u8D25\uFF0C\u8BF7\u91CD\u8BD5\u6216\u76F4\u63A5\u590D\u5236\u4E0A\u65B9\u94FE\u63A5', true);
      });
  }

  function setDirty(d) {
    dirty = d;
    $('gen-btn').classList.toggle('dirty', d);
    $('gen-btn').textContent = d ? '\u53C2\u6570\u5DF2\u4FEE\u6539 \xB7 \u70B9\u51FB\u66F4\u65B0' : '\u751F\u6210\u94FE\u63A5';
    ['state', 'action-state'].forEach(function (id) {
      $(id).className = 'tag ' + (d ? 'stale' : 'ok');
      $(id).textContent = d ? '\u672A\u66F4\u65B0' : '\u5DF2\u751F\u6210';
    });
    var pill = $('top-state');
    pill.className = 'pill ' + (d ? 'stale' : 'ok');
    pill.textContent = d ? '\u5F85\u66F4\u65B0' : '\u5DF2\u5C31\u7EEA';
  }

  function markDirty() {
    if (dirty) return;
    if (qrLink) {
      qrLink = '';
      clearQR('\u53C2\u6570\u5DF2\u53D8\u66F4\uFF0C\u8BF7\u91CD\u65B0\u751F\u6210\u4E8C\u7EF4\u7801', false);
    }
    setDirty(true);
  }

  function copy(text, btn) {
    if (!text) return;
    function done() {
      btn.textContent = '\u5DF2\u590D\u5236';
      clearTimeout(copyTimers[btn.id]);
      copyTimers[btn.id] = setTimeout(function () { btn.textContent = '\u590D\u5236'; }, 1600);
    }
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.top = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (e) {}
      document.body.removeChild(ta);
      done();
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else {
      fallback();
    }
  }

  function parseLink(raw) {
    var m = String(raw).trim().match(/^(socks|socks5|http|https):\\/\\/(?:([^:@\\/]*):?([^@\\/]*)@)?(\\[[^\\]]+\\]|[^:\\/?#]+):(\\d{1,5})\\/?$/i);
    if (!m) return null;
    try {
      return {
        scheme: m[1].toLowerCase(),
        user: decodeURIComponent(m[2] || ''),
        pass: decodeURIComponent(m[3] || ''),
        host: m[4],
        port: m[5]
      };
    } catch (e) {
      return null;
    }
  }

  function applyLink(raw) {
    var p = parseLink(raw);
    if (!p) return;
    var global = (function () { var t = ptypeVal(); return t === 'g5' || t === 'gh'; })();
    var socks = p.scheme === 'socks' || p.scheme === 'socks5';
    setPtype(global ? (socks ? 'g5' : 'gh') : (socks ? 's5' : 'h'));
    $('pr-host').value = p.host + ':' + p.port;
    $('pr-user').value = p.user;
    $('pr-pass').value = p.pass;
    $('pr-link').value = '';
    uf();
    ph();
    generate();
  }

  function reset() {
    setPtype('direct');
    $('ip-host').value = '';
    $('pr-link').value = '';
    $('pr-host').value = '';
    $('pr-user').value = '';
    $('pr-pass').value = '';
    $('nm').value = 'SuperEdge\u91D1\u4E1D\u96C0';
    $('sv-addr').value = '';
    $('sv-port').value = '';
    $('sv-err').textContent = '';
    setLL('0');
    setPath('');
    uf();
    ph();
    renderLL();
    generate();
  }

  function bind() {
    document.querySelectorAll('input[name="ptype"]').forEach(function (el) {
      el.addEventListener('change', function () { uf(); ph(); markDirty(); });
    });
    ['ip-host', 'pr-host', 'pr-user', 'pr-pass', 'nm', 'sv-addr', 'sv-port'].forEach(function (id) {
      $(id).addEventListener('input', function () {
        if (id === 'sv-addr' || id === 'sv-port') $('sv-err').textContent = '';
        markDirty();
      });
    });
    document.querySelectorAll('input[name="ll"]').forEach(function (el) {
      el.addEventListener('change', function () { renderLL(); markDirty(); });
    });
    document.querySelectorAll('input[name="path"]').forEach(function (el) {
      el.addEventListener('change', markDirty);
    });

    var timer = 0;
    $('pr-link').addEventListener('input', function () {
      var value = this.value;
      clearTimeout(timer);
      timer = setTimeout(function () { applyLink(value); }, 300);
    });

    $('gen-btn').addEventListener('click', generate);
    $('reset-btn').addEventListener('click', reset);
    $('cp-uuid').addEventListener('click', function () { copy(uuid, this); });
    $('id-eye').addEventListener('click', toggleId);
    $('qr-gen').addEventListener('click', makeQR);
    $('cp-vless').addEventListener('click', function () { copy($('out-vless').value, this); });
    $('cp-path').addEventListener('click', function () { copy($('out-path').value, this); });

    $('qr-img').addEventListener('click', function () {
      if (!this.src) return;
      var zoom = $('qr-zoom');
      zoom.querySelector('img').src = this.src;
      zoom.classList.add('open');
      zoom.setAttribute('aria-hidden', 'false');
    });
    $('qr-zoom').addEventListener('click', function () {
      this.classList.remove('open');
      this.setAttribute('aria-hidden', 'true');
    });

    var links = Array.prototype.slice.call(document.querySelectorAll('.rail-item'));
    var blocks = links.map(function (a) {
      return document.querySelector(a.getAttribute('href'));
    });
    function activate(i) {
      links.forEach(function (a, k) { a.classList.toggle('is-active', k === i); });
    }
    links.forEach(function (a, i) {
      a.addEventListener('click', function () { activate(i); });
    });
    if ('IntersectionObserver' in window) {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
          if (!en.isIntersecting) return;
          activate(blocks.indexOf(en.target));
        });
      }, { rootMargin: '-30% 0px -55% 0px', threshold: 0 });
      blocks.forEach(function (b) { if (b) io.observe(b); });
    }
  }

  $('sv-addr').placeholder = location.hostname || '\u5F53\u524D\u57DF\u540D';
  $('sv-port').placeholder = location.port || '443';

  $('lock-btn').addEventListener('click', lock);
  $('theme-btn').addEventListener('click', cycleTheme);

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      var zoom = $('qr-zoom');
      zoom.classList.remove('open');
      zoom.setAttribute('aria-hidden', 'true');
    }
  });

  readTheme();
  applyTheme();
  if (mql) {
    if (mql.addEventListener) mql.addEventListener('change', applyTheme);
    else if (mql.addListener) mql.addListener(applyTheme);
  }
  initIdle();
  bind();
  showApp();
})();
`;var esc2=s=>String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");var PATH_OPTIONS=CFG.pathPrefix.map((p,i)=>`<label class="opt mono"><input type="radio" name="path" value="${esc2(p)}"${i===0?" checked":""}><span class="opt-body"><b>${esc2(p)}</b></span></label>`).join("");var LL_DATA=Object.fromEntries(Object.entries(LL_MAP).map(([ll,key])=>{const p=PROFILES[key];return[ll,{chunk:p.chunk,dnPack:p.dnPack,upPack:p.upPack,stagger:p.stagger,totalTimeout:p.totalTimeout,dnHigh:p.dnHigh}]}));var renderPanel2=nodeIdJson=>panel_default.split("<!-- __PANEL2_STYLE__ -->").join(`<style>${panel_default2}</style>`).split("<!-- __PANEL2_DATA__ -->").join(`<script>var NODE_ID = ${nodeIdJson};
var LL_PROFILES = ${JSON.stringify(LL_DATA)};</script>`).split("<!-- __PANEL2_SCRIPT__ -->").join(`<script>${panel_default3}</script>`).split("__PATH_OPTIONS__").join(PATH_OPTIONS);var parseStrategy=searchParams=>{const llRaw=searchParams.get("ll")||"0";const profileKey=LL_MAP[llRaw]||"default";const profile=PROFILES[profileKey];const s={profile,globalGW:null,localSocks:null,localHttp:null,gwIP:null,concur:CFG.concur};const rawS5=searchParams.get("s5");if(rawS5){const p=parseProxyURL(rawS5);if(p&&p.type==="S5")s.localSocks=p}const rawH=searchParams.get("h");if(rawH){const p=parseProxyURL(rawH);if(p&&p.type==="H")s.localHttp=p}const rawG5=searchParams.get("g5");if(rawG5){const p=parseProxyURL(rawG5);if(p&&p.type==="S5")s.globalGW=p}const rawGH=searchParams.get("gh");if(rawGH){const p=parseProxyURL(rawGH);if(p&&p.type==="H")s.globalGW=p}const ipRaw=searchParams.get("ip")||searchParams.get("proxyip");if(ipRaw){const[a,p=443]=parseAddressPort(ipRaw);s.gwIP={address:a.startsWith("[")?a.slice(1,-1):a,port:+p}}return s};var PANEL_INNER_HTML=`<div class=meta id=meta></div>

<div class=field>
  <label>\u51FA\u7AD9\u65B9\u5F0F</label>
  <select id=ptype>
    <option value=direct>\u7EAF\u76F4\u8FDE\uFF08\u63A8\u8350\uFF09</option>
    <option value=ip>proxyip \u4E2D\u8F6C</option>
    <option value=s5>SOCKS5 \u5907\u7528</option>
    <option value=h>HTTP \u5907\u7528</option>
    <option value=g5>SOCKS5 \u5168\u5C40</option>
    <option value=gh>HTTP \u5168\u5C40</option>
  </select>
  <div id=ptype-hint class=hint-box></div>
</div>

<div id=f-ip class="field collapse">
  <label>proxyip \u5730\u5740</label>
  <input id=ip-host type=text placeholder="\u4F8B\u5982 1.2.3.4:443">
  <div class=hint-inline>\u7B2C\u4E09\u65B9\u4E2D\u8F6C\u8282\u70B9\u7684\u5730\u5740\uFF0C\u76F4\u8FDE\u5931\u8D25\u65F6\u81EA\u52A8\u542F\u7528</div>
</div>

<div id=f-proxy class=collapse>
  <div class=field>
    <label>\u7C98\u8D34\u4EE3\u7406\u94FE\u63A5\uFF08\u53EF\u9009\uFF09</label>
    <input id=pr-link type=text placeholder="socks5://user:pass@host:port">
    <div class=hint-inline>\u7C98\u8D34\u5B8C\u6574\u94FE\u63A5\u53EF\u81EA\u52A8\u586B\u5145\u4EE5\u4E0B\u5B57\u6BB5</div>
  </div>
  <div class=field>
    <label>\u4EE3\u7406\u5730\u5740</label>
    <input id=pr-host type=text placeholder="\u4F8B\u5982 1.2.3.4:1080">
    <div class=hint-inline>\u683C\u5F0F\u4E3A host:port</div>
  </div>
  <div class=row>
    <div class=field>
      <label>\u7528\u6237\u540D\uFF08\u53EF\u9009\uFF09</label>
      <input id=pr-user type=text placeholder="\u4EE3\u7406\u9700\u8981\u8BA4\u8BC1\u65F6\u586B\u5199">
    </div>
    <div class=field>
      <label>\u5BC6\u7801\uFF08\u53EF\u9009\uFF09</label>
      <input id=pr-pass type=text placeholder="\u4EE3\u7406\u9700\u8981\u8BA4\u8BC1\u65F6\u586B\u5199">
    </div>
  </div>
</div>

<div class=field>
  <label>\u8282\u70B9\u540D\u79F0</label>
  <input id=nm type=text value="SuperEdge\u91D1\u4E1D\u96C0">
  <div class=hint-inline>\u663E\u793A\u5728\u5BA2\u6237\u7AEF\u8282\u70B9\u5217\u8868\u91CC\u7684\u540D\u79F0</div>
</div>

<div class=row>
  <div class=field>
    <label>\u81EA\u5B9A\u4E49\u670D\u52A1\u5668\uFF08\u4F18\u9009 IP / \u57DF\u540D\uFF09</label>
    <input id=sv-addr type=text placeholder="\u7559\u7A7A\u5219\u4F7F\u7528\u5F53\u524D\u57DF\u540D">
  </div>
  <div class="field port">
    <label>\u7AEF\u53E3</label>
    <input id=sv-port type=text inputmode=numeric placeholder=443>
  </div>
</div>
<div class=hint-inline>\u586B Cloudflare \u4F18\u9009 IP \u6216\u81EA\u5B9A\u4E49\u57DF\u540D \xB7 \u7AEF\u53E3\u4EC5\u652F\u6301 443 / 2053 / 2083 / 2087 / 2096 / 8443</div>
<div id=sv-err class=sv-err></div>

<div class=field>
  <label>\u4F20\u8F93\u6863\u4F4D</label>
  <select id=ll-mode>
    <option value=0>\u5747\u8861\u6A21\u5F0F \xB7 ll=0\uFF08\u9ED8\u8BA4\uFF0C\u63A8\u8350\uFF09</option>
    <option value=1>\u4F4E\u5EF6\u8FDF\u6A21\u5F0F \xB7 ll=1\uFF08\u26A0\uFE0F \u6FC0\u8FDB\uFF09</option>
    <option value=2>\u9AD8\u901F\u4E0B\u8F7D\u6A21\u5F0F \xB7 ll=2\uFF08\u26A0\uFE0F \u6FC0\u8FDB\uFF09</option>
  </select>
  <div id=ll-hint class=hint-box></div>
</div>

<div class=field>
  <label>\u63A5\u5165\u8DEF\u5F84</label>
  <select id=path-sel>
    ${CFG.pathPrefix.map(p=>'<option value="'+p+'">'+p+"</option>").join("")}
  </select>
  <div class=hint-inline>\u4F2A\u88C5\u8DEF\u5F84 \xB7 \u9700\u4E0E\u5BA2\u6237\u7AEF WebSocket Path \u5B8C\u5168\u4E00\u81F4 \xB7 \u67D0\u6761\u8DEF\u5F84\u88AB\u5C01\u9501\u65F6\u53EF\u5207\u6362\u5176\u4F59\u8DEF\u5F84\uFF0C\u670D\u52A1\u7AEF\u65E0\u9700\u6539\u52A8</div>
</div>

<div class=divider>
  <h4>\u751F\u6210\u7ED3\u679C</h4>
  <button id=gen-btn class=gen>\u751F\u6210</button>
  <div class=actions><button id=reset-btn class=ghost>\u91CD\u7F6E</button></div>

  <div class=out-label>\u2460 \u590D\u5236 VLESS \u94FE\u63A5\uFF08\u63A8\u8350\uFF0C\u4E00\u6B65\u5230\u4F4D\uFF09</div>
  <div class=out-row>
    <input id=out-vless type=text readonly onclick="this.select()" placeholder="vless://...">
    <button class=sec id=cp-vless>\u590D\u5236</button>
    <span class=ok id=ok-vless></span>
  </div>

  <div class=out-label>\u2461 \u5355\u72EC\u590D\u5236 Path\uFF08\u4EC5\u5F53\u5BA2\u6237\u7AEF\u4E0D\u652F\u6301\u5BFC\u5165\u5206\u4EAB\u94FE\u63A5\u65F6\u4F7F\u7528\uFF09</div>
  <div class=out-row>
    <input id=out-path type=text readonly onclick="this.select()" placeholder="${CFG.pathPrefix[0]}?...">
    <button class=sec id=cp-path>\u590D\u5236</button>
    <span class=ok id=ok-path></span>
  </div>

  <div class=out-label>\u2462 \u626B\u7801\u5BFC\u5165\uFF08\u624B\u673A\u5BA2\u6237\u7AEF \xB7 \u70B9\u51FB\u4E8C\u7EF4\u7801\u653E\u5927\uFF09</div>
  <div class=qr-box>
    <img id=qr-img alt="\u8282\u70B9\u4E8C\u7EF4\u7801" width=320 height=320 style=display:none>
    <div id=qr-tip class=qr-tip>\u6B63\u5728\u751F\u6210\u2026</div>
    <div class=qr-note>\u4E8C\u7EF4\u7801\u7531 qr.tgds.eu.org \u751F\u6210\uFF0C\u5185\u5BB9\u542B\u8282\u70B9UUID\uFF0C\u8BF7\u52FF\u622A\u56FE\u5916\u4F20</div>
  </div>

  <div class=usage-tip>
    \u{1F4A1} <b>\u4F7F\u7528\u65B9\u5F0F</b><br>
    \u7535\u8111\u7AEF\uFF1A\u5BFC\u5165 \u2460 \u7684\u94FE\u63A5\u5373\u53EF\uFF08Xray / Sing-box / v2rayN / Clash Meta\uFF09\u3002<br>
    \u624B\u673A\u7AEF\uFF1A\u70B9\u51FB \u2462 \u7684\u4E8C\u7EF4\u7801\u653E\u5927\u540E\u626B\u63CF\u3002<br>
    \u4EC5\u5F53\u5BA2\u6237\u7AEF\u8981\u6C42\u624B\u52A8\u586B Path \u65F6\u624D\u9700\u8981 \u2461\u3002
  </div>
</div>

<div id=qr-zoom class=qr-zoom><img alt="\u8282\u70B9\u4E8C\u7EF4\u7801"></div>

<p class=foot>
  <span class=warn>\u26A0\uFE0F \u6B64\u9875\u9762\u5305\u542B\u8282\u70B9UUID\uFF0C\u8BF7\u52FF\u5206\u4EAB\u622A\u56FE\u6216\u94FE\u63A5</span>
  <span class=ver>v1.9.3</span>
</p>`;var _encUuid=null;var getEncryptedUuid=async()=>{if(_encUuid)return _encUuid;const salt=crypto.getRandomValues(new Uint8Array(16));const iv=crypto.getRandomValues(new Uint8Array(12));const keyMat=await crypto.subtle.importKey("raw",ENC.encode(CFG.panelPin),"PBKDF2",false,["deriveKey"]);const key=await crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:1e5,hash:"SHA-256"},keyMat,{name:"AES-GCM",length:256},false,["encrypt"]);const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,ENC.encode(CFG.id));const toB64=u8=>btoa(String.fromCharCode(...u8));_encUuid={salt:toB64(salt),iv:toB64(iv),ct:toB64(new Uint8Array(ct))};return _encUuid};var renderPanel=(encJson,panelHtmlJson)=>{return`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${SITE_META.title}</title>
<meta name="description" content="${SITE_META.desc}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>
:root{--bg:#f1f1f1;--ink:#333;--muted:#999;--line:#e5e7eb;--accent:#e05454;--accent-hover:#c94848;--warn:#f59e0b;--warn-hover:#d97706;--info:#3b82f6;--mono:ui-monospace,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;margin:0;padding:0;line-height:1.65}
.container{max-width:960px;margin:0 auto;padding:56px 24px 0}
h1{font-size:30px;margin:0 0 12px;color:var(--ink);font-weight:600;letter-spacing:-.01em}
h2{font-size:20px;margin:0 0 20px;color:#666;font-weight:400}
p{font-size:15px;color:var(--muted);line-height:1.7;max-width:640px;margin:0 0 10px}
#trigger{cursor:pointer;user-select:none}
.links a{color:var(--accent);text-decoration:none;margin-right:18px;font-size:14px}
.links a:hover{text-decoration:underline}
.cover-foot{display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px;max-width:960px;margin:48px auto 0;padding:22px 24px 28px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
#pn{position:fixed;right:16px;top:16px;width:400px;max-width:calc(100vw - 32px);max-height:calc(100vh - 32px);overflow-y:auto;padding:18px;background:#fff;border-radius:10px;box-shadow:0 6px 28px rgba(0,0,0,.18);border:1px solid var(--line);display:none;text-align:left;font-size:13px;z-index:9999}
#pn h3{margin:0 0 6px;font-size:15px;font-weight:600}
#pn h4{margin:0 0 10px;font-size:13px;font-weight:600}
#pn .close{float:right;cursor:pointer;color:#bbb;font-size:20px;line-height:1;user-select:none}
#pn .close:hover{color:#666}
.meta{display:grid;grid-template-columns:auto 1fr;column-gap:10px;row-gap:4px;align-items:baseline;font-size:11px;background:#fafafa;border:1px dashed var(--line);border-radius:5px;padding:8px 10px;margin-bottom:14px}
.meta .k{color:#999;white-space:nowrap}
.meta .v{color:var(--accent);font-family:var(--mono);font-weight:600;word-break:break-all;line-height:1.4}
.field{margin-bottom:12px}
label{display:block;font-size:12px;color:#666;margin-bottom:4px;font-weight:500}
input[type=text],input[type=password],select{width:100%;padding:7px 9px;border:1px solid #ddd;border-radius:5px;font-size:12px;font-family:var(--mono);background:#fff;outline:none}
input[type=text]:focus,input[type=password]:focus,select:focus{border-color:var(--accent)}
.row{display:flex;gap:8px}
.row>.field{flex:1}
.collapse{display:none}
.collapse.open{display:block}
.divider{border-top:1px dashed #eee;margin:14px 0;padding-top:12px}
.out-row{display:flex;gap:6px;align-items:center;margin-bottom:6px}
.out-row input{flex:1}
button{padding:7px 12px;border:none;border-radius:5px;background:var(--accent);color:#fff;cursor:pointer;font-size:12px;transition:background .15s}
button:hover{background:var(--accent-hover)}
button.sec{background:#666}
button.sec:hover{background:#555}
button.ghost{background:#fff;color:#666;border:1px solid #ddd}
button.ghost:hover{background:#f5f5f5;color:#333}
button.gen{width:100%;padding:10px 12px;font-size:13px;font-weight:600;margin-bottom:12px}
button.gen.dirty{background:var(--warn)}
button.gen.dirty:hover{background:var(--warn-hover)}
.actions{display:flex;gap:6px;margin-bottom:8px}
.actions button{flex:1}
.ok{color:#2a9d2a;font-size:11px;margin-left:6px}
.foot{margin-top:12px;padding-top:10px;border-top:1px dashed #eee;color:#aaa;font-size:11px;line-height:1.6}
.foot .warn{color:var(--accent);font-weight:600}
.foot .ver{float:right;color:#ccc}
.hint-box{margin-top:6px;font-size:11px;color:#666;line-height:1.7;padding:8px 10px;background:#fafafa;border-left:2px solid #ddd;border-radius:3px;white-space:pre-line}
.hint-box.warn{color:#b45309;background:#fffbeb;border-left-color:var(--warn)}
.hint-inline{margin-top:4px;font-size:11px;color:#999;line-height:1.5}
.row>.field.port{flex:0 0 92px}
.sv-err{color:var(--accent);font-size:11px;line-height:1.5;margin-top:2px}
.out-label{font-size:11px;color:#666;margin:8px 0 4px;font-weight:500}
.usage-tip{margin-top:12px;padding:8px 10px;background:#eff6ff;border-left:2px solid var(--info);border-radius:3px;font-size:11px;color:#1e40af;line-height:1.7}
.qr-box{text-align:center;margin:8px 0 2px}
#qr-img{width:200px;height:200px;background:#fff;border:1px solid var(--line);border-radius:8px;padding:6px;display:block;margin:0 auto;cursor:zoom-in}
.qr-tip{font-size:11px;color:#999;margin-top:6px}
.qr-tip.err{color:var(--accent)}
.qr-note{font-size:10px;color:#bbb;margin-top:2px}
.qr-zoom{position:fixed;inset:0;background:rgba(0,0,0,.78);display:none;align-items:center;justify-content:center;z-index:10000;cursor:zoom-out}
.qr-zoom.open{display:flex}
.qr-zoom img{width:min(86vw,86vh);height:min(86vw,86vh);background:#fff;border-radius:10px;padding:12px}
#lock-layer h3{margin:0 0 4px;font-size:15px;font-weight:600}
#lock-layer .sub{font-size:11px;color:#999;margin:0 0 14px}
#lock-layer .row{display:flex;gap:6px}
#lock-layer input{flex:1;min-width:0}
#lock-layer .err{color:var(--accent);font-size:11px;margin-top:8px;min-height:15px}
.pin-toggle{padding:7px 10px;background:#fff;color:#999;border:1px solid #ddd;border-radius:5px;cursor:pointer;font-size:14px;min-width:38px;flex-shrink:0;line-height:1}
.pin-toggle:hover{background:#f5f5f5;color:#333;border-color:#ccc}
@media(max-width:600px){
  body{padding:0}
  #pn{right:8px;left:8px;top:8px;width:auto;max-height:calc(100vh - 16px);padding:14px}
  .out-row input{font-size:11px}
  button{padding:9px 14px}
}
/* \u2500\u2500 v1.9.2 \u629B\u5149\u5C42\uFF1Atoken / \u6697\u8272 / \u7126\u70B9\u73AF / \u89E6\u63A7 \u2500\u2500 */
:root{--surface:#ffffff;--surface-2:#f8f9fb;--faint:#9aa4b2;--line-strong:#d5dae2;--warn-soft:#fff8e9;--info-soft:#eef4ff;--ok:#16a34a;--radius:14px;--radius-sm:8px;--shadow:0 12px 34px rgba(15,23,42,.16),0 2px 8px rgba(15,23,42,.07);--ring:0 0 0 3px rgba(224,84,84,.16)}
body{transition:background .25s,color .25s}
h2{color:var(--muted)}
#pn{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow);transition:background .25s,border-color .25s}
#pn .close{color:var(--faint)}
#pn .close:hover{color:var(--ink)}
.meta{background:var(--surface-2);border-radius:var(--radius-sm)}
.meta .k{color:var(--faint)}
label{color:var(--muted)}
input[type=text],input[type=password],select{background:var(--surface-2);border:1px solid var(--line-strong);color:var(--ink);border-radius:var(--radius-sm);height:34px;font-size:12.5px;transition:border-color .15s,box-shadow .15s,background .25s}
input::placeholder{color:var(--faint)}
input[type=text]:focus,input[type=password]:focus,select:focus{border-color:var(--accent);box-shadow:var(--ring)}
button{border-radius:var(--radius-sm);transition:background .15s,color .15s,border-color .15s,transform .1s}
button:active{transform:translateY(1px)}
button.sec{background:var(--surface-2);color:var(--muted);border:1px solid var(--line-strong)}
button.sec:hover{background:var(--line);color:var(--ink)}
button.ghost{background:transparent;color:var(--muted);border:1px solid var(--line-strong)}
button.ghost:hover{background:var(--surface-2);color:var(--ink)}
.ok{color:var(--ok)}
.foot{border-top-color:var(--line);color:var(--faint)}
.foot .ver{color:var(--faint)}
.hint-box{background:var(--surface-2);color:var(--muted);border-left-color:var(--line-strong);border-radius:0 var(--radius-sm) var(--radius-sm) 0}
.hint-box.warn{color:var(--warn);background:var(--warn-soft)}
.hint-inline{color:var(--faint)}
.out-label{color:var(--muted)}
.usage-tip{background:var(--info-soft);color:var(--info);border-left-color:var(--info)}
.qr-box{background:var(--surface-2);border:1px solid var(--line);border-radius:var(--radius-sm);padding:12px 10px 8px}
#qr-img{box-shadow:0 2px 8px rgba(0,0,0,.08)}
.qr-tip{color:var(--muted)}
.qr-note{color:var(--faint)}
.qr-zoom img{border-radius:12px}
#lock-layer .sub{color:var(--faint)}
.pin-toggle{background:var(--surface-2);color:var(--muted);border:1px solid var(--line-strong);border-radius:var(--radius-sm);height:34px}
.pin-toggle:hover{color:var(--ink);border-color:var(--accent)}
.divider{border-top-color:var(--line)}
@media (prefers-color-scheme: dark){
  :root{--bg:#0e1320;--ink:#e6eaf2;--muted:#9aa6ba;--faint:#64748f;--line:#28324a;--line-strong:#3a4a6b;--accent:#ff6b6b;--accent-hover:#ef5f5f;--warn:#f5b942;--warn-hover:#eab308;--info:#5fa8f7;--surface:#161c2a;--surface-2:#1d2534;--warn-soft:#332a15;--info-soft:#1a2947;--shadow:0 14px 38px rgba(0,0,0,.55),0 2px 10px rgba(0,0,0,.35);--ring:0 0 0 3px rgba(255,107,107,.28)}
}
@media(max-width:600px){
  input[type=text],input[type=password],select{font-size:16px;height:40px}
  button{min-height:40px}
  #lock-layer .row{flex-wrap:nowrap}
  .pin-toggle{height:40px}
}
</style></head><body>
<div class=container>
<h1>${SITE_META.h1}</h1>
<p>${SITE_META.lead}</p>
<p class=links><a href=/docs>Docs</a><a href=/status>Status</a><a href=/about>About</a></p>
</div>
<footer class=cover-foot><span>&copy; 2026 ${SITE_META.brand} Labs</span><span>This site is served over <span id=trigger>HTTPS</span></span></footer>
<div id=pn><span class=close id=pnc>&times;</span>
<div id=lock-layer>
  <h3>\u8282\u70B9\u751F\u6210\u5668</h3>
  <p class=sub>\u53D7 PIN \u4FDD\u62A4 \xB7 \u7528\u4E8E\u751F\u6210 VLESS \u8282\u70B9\u94FE\u63A5</p>
  <div class=row>
    <input id=pin-input type=password placeholder="PIN" autocomplete=off spellcheck=false>
    <button id=pin-toggle class=pin-toggle type=button title="\u70B9\u51FB\u663E\u793A PIN">&#128065;</button>
    <button id=unlock-btn>\u89E3\u9501</button>
  </div>
  <div class=err id=lock-err></div>
</div>
<div id=panel-content></div></div>
<script>
var ENC_DATA=${encJson};
var PANEL_HTML=${panelHtmlJson};
var _uuid='';

/* ---------- \u4EE3\u7406\u7C7B\u578B\u8BF4\u660E ---------- */
var PTYPE_HINT = {
  'direct': '\u7EAF\u76F4\u8FDE\\nWorker \u76F4\u63A5\u8FDE\u63A5\u76EE\u6807\u670D\u52A1\u5668\uFF0C\u4E0D\u7ECF\u8FC7\u4EFB\u4F55\u4E2D\u8F6C\u3002\\n\\n\u2022 \u4F18\u70B9\uFF1A\u901F\u5EA6\u6700\u5FEB\u3001\u5EF6\u8FDF\u6700\u4F4E\\n\u2022 \u7F3A\u70B9\uFF1A\u76EE\u6807 IP \u88AB\u5899\u65F6\u65E0\u6CD5\u8BBF\u95EE\\n\u2022 \u9002\u5408\uFF1A\u76EE\u6807\u672A\u88AB\u5C01\u9501\u7684\u7EDD\u5927\u591A\u6570\u573A\u666F',
  'ip': 'proxyip \u4E2D\u8F6C\\n\u76F4\u8FDE\u5931\u8D25\u65F6\uFF0C\u901A\u8FC7\u4F60\u63D0\u4F9B\u7684 proxyip \u5730\u5740\u8F6C\u53D1\u3002\\n\\n\u2022 proxyip\uFF1A\u7B2C\u4E09\u65B9\u90E8\u7F72\u7684\u516C\u5F00\u4E2D\u8F6C\u8282\u70B9\\n\u2022 \u4F18\u70B9\uFF1A\u76EE\u6807\u88AB\u5899\u65F6\u4ECD\u53EF\u8BBF\u95EE\\n\u2022 \u7F3A\u70B9\uFF1A\u4E2D\u8F6C\u670D\u52A1\u8D28\u91CF\u53D6\u51B3\u4E8E\u7B2C\u4E09\u65B9\uFF0C\u65E0\u53EF\u7528\u6027\u4FDD\u8BC1\\n\u2022 \u9700\u8981\uFF1A\u586B\u5199 proxyip \u5730\u5740',
  's5': 'SOCKS5 \u5907\u7528\\n\u76F4\u8FDE\u5931\u8D25\u65F6\uFF0C\u8D70\u4F60\u81EA\u5DF1\u7684 SOCKS5 \u4EE3\u7406\u3002\\n\\n\u2022 \u4F18\u70B9\uFF1A\u76F4\u8FDE\u6B63\u5E38\u65F6\u8D70\u76F4\u8FDE\uFF08\u5FEB\uFF09\uFF1B\u76F4\u8FDE\u5931\u8D25\u65F6\u8D70\u4EE3\u7406\uFF08\u901A\uFF09\\n\u2022 \u7F3A\u70B9\uFF1A\u9700\u8981\u989D\u5916\u7EF4\u62A4\u4EE3\u7406\u670D\u52A1\u5668\\n\u2022 \u9700\u8981\uFF1A\u4EE3\u7406\u5730\u5740\u3001\u53EF\u9009\u7528\u6237\u540D\u5BC6\u7801',
  'h': 'HTTP \u5907\u7528\\n\u76F4\u8FDE\u5931\u8D25\u65F6\uFF0C\u8D70\u4F60\u81EA\u5DF1\u7684 HTTP \u4EE3\u7406\uFF08CONNECT \u65B9\u5F0F\uFF09\u3002\\n\\n\u2022 \u540C SOCKS5 \u5907\u7528\uFF0C\u53EA\u662F\u534F\u8BAE\u4E0D\u540C\\n\u2022 \u9002\u5408\uFF1A\u5DF2\u90E8\u7F72 HTTP \u4EE3\u7406\u7684\u573A\u666F',
  'g5': 'SOCKS5 \u5168\u5C40\\n\u6240\u6709\u6D41\u91CF\u90FD\u8D70 SOCKS5 \u4EE3\u7406\uFF0C\u4E0D\u5C1D\u8BD5\u76F4\u8FDE\u3002\\n\\n\u2022 \u4F18\u70B9\uFF1A\u51FA\u53E3 IP \u56FA\u5B9A\uFF0C\u4FBF\u4E8E\u76EE\u6807\u4FA7\u767D\u540D\u5355\u653E\u884C\\n\u2022 \u7F3A\u70B9\uFF1A\u901F\u5EA6\u53D7\u4EE3\u7406\u670D\u52A1\u5668\u9650\u5236\\n\u2022 \u9002\u5408\uFF1A\u76EE\u6807 IP \u5168\u90E8\u88AB\u5C01\u3001\u9700\u8981\u56FA\u5B9A\u51FA\u53E3 IP',
  'gh': 'HTTP \u5168\u5C40\\n\u6240\u6709\u6D41\u91CF\u90FD\u8D70 HTTP \u4EE3\u7406\uFF0C\u4E0D\u5C1D\u8BD5\u76F4\u8FDE\u3002\\n\\n\u2022 \u540C SOCKS5 \u5168\u5C40\uFF0C\u53EA\u662F\u534F\u8BAE\u4E0D\u540C'
};

/* ---------- \u4F20\u8F93\u6863\u4F4D\u8BF4\u660E ---------- */
var LL_HINT = {
  '0': '\u5747\u8861\u6A21\u5F0F \xB7 ll=0\\n\\n\u53C2\u6570\uFF1A\\n  \u5C0F\u5305\u5408\u5E76      48 KB \u4E00\u5E27\\n  \u5207\u6362\u5907\u7528      \u76F4\u8FDE\u5931\u8D25 1 \u79D2\u540E\\n  \u5168\u5C40\u8D85\u65F6      6 \u79D2\\n\\n\u9002\u5408\uFF1A\u7F51\u9875\u6D4F\u89C8\u3001\u5728\u7EBF\u89C6\u9891\u3001\u65E5\u5E38\u4EE3\u7406\\n\u98CE\u9669\uFF1A\u65E0\uFF08\u9ED8\u8BA4\u914D\u7F6E\uFF09',
  '1': '\u4F4E\u5EF6\u8FDF\u6A21\u5F0F \xB7 ll=1  \u26A0\uFE0F \u6FC0\u8FDB\\n\\n\u53C2\u6570\uFF1A\\n  \u5C0F\u5305\u5408\u5E76      \u5C0F\u5305\u4E0D\u7B49\u5F85\uFF0C\u51D1\u6EE1 8 KB \u5373\u53D1\\n  \u5207\u6362\u5907\u7528      \u76F4\u8FDE\u65E0\u54CD\u5E94 0.2 \u79D2\u540E\\n  \u5168\u5C40\u8D85\u65F6      3 \u79D2\\n\\n\u9002\u5408\uFF1ASSH\u3001\u8FDC\u7A0B\u684C\u9762\u3001\u6E38\u620F\u3001\u5B9E\u65F6\u901A\u4FE1\\n\u4EE3\u4EF7\uFF1A\u5907\u7528\u8DEF\u5F84\u9891\u7E41\u542F\u52A8\uFF0C\u53EF\u80FD\u8BEF\u5224\u6162\u670D\u52A1\u5668',
  '2': '\u9AD8\u901F\u4E0B\u8F7D\u6A21\u5F0F \xB7 ll=2  \u26A0\uFE0F \u6FC0\u8FDB\\n\\n\u53C2\u6570\uFF1A\\n  \u8BFB\u53D6\u5927\u5C0F      \u5355\u6B21 256 KB\\n  \u5C0F\u5305\u5408\u5E76      256 KB \u4E00\u5E27\\n  \u80CC\u538B\u7F13\u51B2      10 MB\uFF08\u8D85\u8FC7\u5373\u6682\u505C\u8BFB\u53D6\u4E0A\u6E38\uFF09\\n  \u5168\u5C40\u8D85\u65F6      12 \u79D2\\n\\n\u9002\u5408\uFF1AGooglePlay\u3001AppStore\u3001Steam\u3001\u7F51\u76D8\u5927\u6587\u4EF6\u4E0B\u8F7D\\n\u4EE3\u4EF7\uFF1A\u5355\u4F1A\u8BDD\u5185\u5B58\u7EA6 10 MB\uFF0C\u5EFA\u8BAE\u540C\u65F6\u4E0B\u8F7D\u4EBA\u6570 \u22643'
};

function b64U8(b){var bin=atob(b),o=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)o[i]=bin.charCodeAt(i);return o}
async function tryDecrypt(pin){var en=new TextEncoder(),salt=b64U8(ENC_DATA.salt),iv=b64U8(ENC_DATA.iv),ct=b64U8(ENC_DATA.ct);var km=await crypto.subtle.importKey('raw',en.encode(pin),'PBKDF2',false,['deriveKey']);var key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:salt,iterations:100000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['decrypt']);var p=await crypto.subtle.decrypt({name:'AES-GCM',iv:iv},key,ct);return new TextDecoder().decode(p)}

var _pi=false;
function initPanel(){
if(_pi)return;_pi=true;
var $=function(id){return document.getElementById(id)},GB=$('gen-btn'),dirty=false,TR=0;

function md(){if(dirty)return;dirty=true;GB.classList.add('dirty');GB.textContent='\u53C2\u6570\u5DF2\u4FEE\u6539 \xB7 \u70B9\u51FB\u66F4\u65B0\u94FE\u63A5\u4E0E\u4E8C\u7EF4\u7801'}
function cd(){dirty=false;GB.classList.remove('dirty');GB.textContent='\u751F\u6210'}

function pp(r){
  if(!r)return null;
  var m=r.match(/^(socks5?|https?):[/]{2}(.+)$/i);
  if(!m)return null;
  var pr=m[1].toLowerCase(),rest=m[2],u='',pw='',hp=rest;
  var at=rest.lastIndexOf('@');
  if(at!==-1){
    var a=rest.substring(0,at);
    hp=rest.substring(at+1);
    var c=a.indexOf(':');
    if(c!==-1){u=a.substring(0,c);pw=a.substring(c+1)}else u=a;
  }
  var h=hp,po='';
  if(hp.charAt(0)==='['){
    var cm=hp.match(/^\\[(.+?)\\](?::(\\d+))?$/);
    if(cm){h='['+cm[1]+']';po=cm[2]||''}
  } else {
    var ci=hp.lastIndexOf(':');
    if(ci!==-1){h=hp.substring(0,ci);po=hp.substring(ci+1)}
  }
  return {proto:pr,user:u,pass:pw,host:h,port:po};
}

function al(r){
  var p=pp(r.trim());
  if(!p)return false;
  $('pr-host').value=p.host+(p.port?':'+p.port:'');
  $('pr-user').value=p.user;
  $('pr-pass').value=p.pass;
  var s=/socks/.test(p.proto),cu=$('ptype').value,gl=cu==='g5'||cu==='gh';
  $('ptype').value=gl?(s?'g5':'gh'):(s?'s5':'h');
  return true;
}

function gp(){
  var t=$('ptype').value,ps=['ed=2560'];
  var ll=$('ll-mode').value;
  if(ll!=='0')ps.push('ll='+ll);
  if(t==='ip'){
    var ip=$('ip-host').value.trim();
    if(ip)ps.push('ip='+encodeURIComponent(ip))
  } else if(t==='s5'||t==='h'||t==='g5'||t==='gh'){
    var h=$('pr-host').value.trim(),u=$('pr-user').value.trim(),pw=$('pr-pass').value.trim();
    if(h){
      var pr=t==='s5'||t==='g5'?'socks5://':'http://',a='';
      if(u&&pw)a=u+':'+pw+'@';else if(u)a=u+'@';
      ps.push(t+'='+encodeURIComponent(pr+a+h))
    }
  }
  return $('path-sel').value+'?'+ps.join('&')
}

/* ---------- \u670D\u52A1\u5668\u4E0E\u7AEF\u53E3 ---------- */
function sv(){
  var e=$('sv-err'),a=$('sv-addr').value.trim(),p=$('sv-port').value.trim();
  e.textContent='';
  a=a.replace(/^[a-z][a-z0-9+.-]*:[/]{2}/i,'').split(/[/?#]/)[0];
  var m=a.match(/^([^:\\[\\]]+):(\\d{1,5})$/);
  if(m){a=m[1];if(!p)p=m[2]}
  if(!a)a=location.hostname||location.host;
  if((a.match(/:/g)||[]).length>1&&a.charAt(0)!=='[')a='['+a+']';
  if(!/^[A-Za-z0-9._\\[\\]:-]+$/.test(a)){
    e.textContent='\u670D\u52A1\u5668\u5730\u5740\u683C\u5F0F\u4E0D\u6B63\u786E\uFF0C\u8BF7\u586B IP \u6216\u57DF\u540D\uFF08\u4E0D\u542B\u534F\u8BAE\u4E0E\u8DEF\u5F84\uFF09';return null
  }
  if(!p)p=location.port||'443';
  if(!/^\\d{1,5}$/.test(p)||+p<1||+p>65535){
    e.textContent='\u7AEF\u53E3\u9700\u4E3A 1-65535 \u7684\u6574\u6570';return null
  }
  return {addr:a,port:p}
}

function gv(){
  var h=location.host,u=_uuid,p=gp(),n=$('nm').value||'SuperEdge\u91D1\u4E1D\u96C0',t=sv();
  if(!u)return '\u8282\u70B9UUID \u672A\u914D\u7F6E';
  if(!t)return '';
  var q='encryption=none&security=tls&sni='+encodeURIComponent(h)+'&type=ws&host='+encodeURIComponent(h)+'&path='+encodeURIComponent(p);
  return 'vless://'+u+'@'+t.addr+':'+t.port+'?'+q+'#'+encodeURIComponent(n)
}

/* ---------- \u4E8C\u7EF4\u7801\uFF08qr.tgds.eu.org\uFF09 ---------- */
var _qrUrl='',_qrSeq=0;
function qrd(u){
  var im=$('qr-img'),tp=$('qr-tip'),n=++_qrSeq;
  im.style.display='none';im.removeAttribute('src');
  if(!u||u.indexOf('vless://')!==0){tp.className='qr-tip err';tp.textContent='\u94FE\u63A5\u672A\u751F\u6210\uFF0C\u65E0\u6CD5\u663E\u793A\u4E8C\u7EF4\u7801';return}
  tp.className='qr-tip';tp.textContent='\u6B63\u5728\u751F\u6210\u4E8C\u7EF4\u7801\u2026';
  fetch('https://qr.tgds.eu.org/api/qrcode?text='+encodeURIComponent(u)+'&level=M&size=320&format=svg')
    .then(function(r){if(!r.ok)throw new Error('qr http '+r.status);return r.blob()})
    .then(function(b){
      if(n!==_qrSeq)return;
      if(_qrUrl)URL.revokeObjectURL(_qrUrl);
      _qrUrl=URL.createObjectURL(b);
      im.src=_qrUrl;
      im.style.display='block';
      tp.textContent='\u624B\u673A\u5BA2\u6237\u7AEF\u626B\u7801\u5373\u53EF\u5BFC\u5165 \xB7 \u70B9\u51FB\u4E8C\u7EF4\u7801\u653E\u5927';
    })
    .catch(function(){
      if(n!==_qrSeq)return;
      if(_qrUrl){URL.revokeObjectURL(_qrUrl);_qrUrl=''}
      im.removeAttribute('src');
      im.style.display='none';
      tp.className='qr-tip err';
      tp.textContent='\u4E8C\u7EF4\u7801\u751F\u6210\u5931\u8D25\uFF0C\u8BF7\u4F7F\u7528 \u2460 \u7684\u94FE\u63A5\u5BFC\u5165';
    });
}

function dg(){var p=gp(),v=gv();$('out-path').value=v?p:'';$('out-vless').value=v;qrd(v);if(v)cd()}

function ra(){
  $('ptype').value='direct';
  $('ip-host').value='';
  $('pr-link').value='';
  $('pr-host').value='';
  $('pr-user').value='';
  $('pr-pass').value='';
  $('nm').value='SuperEdge\u91D1\u4E1D\u96C0';
  $('sv-addr').value='';
  $('sv-port').value='';
  $('sv-err').textContent='';
  $('ll-mode').value='0';
  $('path-sel').selectedIndex=0;
  uf();ph();lh();dg();
}

function uf(){
  var t=$('ptype').value;
  $('f-ip').classList.toggle('open',t==='ip');
  $('f-proxy').classList.toggle('open',t==='s5'||t==='h'||t==='g5'||t==='gh');
}

function ph(){
  var t=$('ptype').value;
  $('ptype-hint').textContent=PTYPE_HINT[t]||'';
}

function lh(){
  var v=$('ll-mode').value,h=$('ll-hint');
  h.textContent=LL_HINT[v]||'';
  h.className='hint-box'+(v==='0'?'':' warn');
}

function cf(ii,oi){
  var el=$(ii),ok=$(oi);
  if(!el.value)return;
  var d=function(){ok.textContent='\u5DF2\u590D\u5236';setTimeout(function(){ok.textContent=''},2000)};
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(el.value).then(d,function(){el.select();document.execCommand('copy');d()});
  } else {
    el.select();document.execCommand('copy');d()
  }
}

$('ptype').addEventListener('change',function(){uf();ph();md()});
['ip-host','pr-host','pr-user','pr-pass','nm','sv-addr','sv-port'].forEach(function(id){$(id).addEventListener('input',md)});
['sv-addr','sv-port'].forEach(function(id){$(id).addEventListener('input',function(){$('sv-err').textContent=''})});
$('ll-mode').addEventListener('change',function(){lh();md()});
$('path-sel').addEventListener('change',md);
GB.addEventListener('click',dg);
$('reset-btn').addEventListener('click',ra);
$('pr-link').addEventListener('input',function(){
  var self=this;
  clearTimeout(TR);
  TR=setTimeout(function(){
    var v=self.value.trim();
    if(!v)return;
    if(al(v)){self.value='';uf();ph();dg()}
  },300)
});
$('cp-path').addEventListener('click',function(){cf('out-path','ok-path')});
$('cp-vless').addEventListener('click',function(){cf('out-vless','ok-vless')});
$('qr-img').addEventListener('click',function(){
  if(!this.getAttribute('src'))return;
  var z=$('qr-zoom');
  z.querySelector('img').src=this.src;
  z.classList.add('open');
});
$('qr-zoom').addEventListener('click',function(){this.classList.remove('open')});

function rm(){
  $('meta').innerHTML='<div class=k>\u8282\u70B9UUID</div><div class=v>'+(_uuid||'\u672A\u914D\u7F6E')+'</div><div class=k>Host</div><div class=v>'+(location.host||'\u672A\u77E5')+'</div>'
}

$('sv-addr').placeholder=location.hostname||'\u5F53\u524D\u57DF\u540D';
$('sv-port').placeholder=location.port||'443';
uf();ph();lh();rm();dg();
}

async function tryUnlock(){
  var pi=document.getElementById('pin-input'),
      ee=document.getElementById('lock-err'),
      pin=pi.value;
  if(!pin){ee.textContent='\u8BF7\u8F93\u5165 PIN';return}
  if(pin.length<8){ee.textContent='PIN \u81F3\u5C11 8 \u4F4D';return}
  ee.textContent='\u6B63\u5728\u9A8C\u8BC1\u2026';ee.style.color='var(--muted)';
  try{
    var uuid=await tryDecrypt(pin);
    if(!uuid||uuid.length<32)throw new Error('\u89E3\u5BC6\u7ED3\u679C\u5F02\u5E38');
    _uuid=uuid;
    document.getElementById('panel-content').innerHTML=PANEL_HTML;
    document.getElementById('lock-layer').style.display='none';
    initPanel();
  }catch(e){
    ee.textContent='PIN \u9519\u8BEF\uFF0C\u8BF7\u91CD\u8BD5';
    ee.style.color='var(--accent)';
    pi.value='';
    pi.focus();
  }
}

(function(){
  var pn=document.getElementById('pn'),tr=document.getElementById('trigger');
  function tp(s){pn.style.display=s?'block':'none'}
  tr.addEventListener('click',function(){tp(pn.style.display!=='block')});
  document.getElementById('pnc').addEventListener('click',function(){tp(false)});
  document.getElementById('unlock-btn').addEventListener('click',tryUnlock);
  document.getElementById('pin-input').addEventListener('keydown',function(e){if(e.key==='Enter')tryUnlock()});
  document.getElementById('pin-toggle').addEventListener('click',function(){
    var pin=document.getElementById('pin-input');
    if(pin.type==='password'){
      pin.type='text';
      this.textContent='\u{1F648}';
      this.title='\u70B9\u51FB\u9690\u85CF PIN';
    } else {
      pin.type='password';
      this.textContent='\u{1F441}';
      this.title='\u70B9\u51FB\u663E\u793A PIN';
    }
  });
  document.getElementById('pin-input').focus();
})();
</script></body></html>`};var SESSION_COOKIE="lumen_sid";var SESSION_TTL=12*60*60;var AUTH_WINDOW=10*60*1e3;var AUTH_LIMIT=60;var AUTH_FAIL_DELAY=300;var AUTH_ENC=new TextEncoder;var safeEqual=(a,b)=>{const x=String(a);const y=String(b);let diff=x.length^y.length;const n=Math.max(x.length,y.length);for(let i=0;i<n;i++){diff|=(x.charCodeAt(i)||0)^(y.charCodeAt(i)||0)}return diff===0};var normId=v=>String(v==null?"":v).replace(/[^0-9a-fA-F]/g,"").toLowerCase();var EXPECTED_ID=normId(CFG.id);var EXPECTED_PIN=String(CFG.panelPin);var credentialsMatch=(id,key)=>{const idOk=safeEqual(normId(id),EXPECTED_ID);const pinOk=safeEqual(String(key==null?"":key),EXPECTED_PIN);return idOk&&pinOk};var _sessionKey=null;var sessionKey=()=>{if(!_sessionKey){_sessionKey=(async()=>{const material=await crypto.subtle.digest("SHA-256",AUTH_ENC.encode("lumen-session|"+CFG.id+"|"+CFG.panelPin));return crypto.subtle.importKey("raw",material,{name:"HMAC",hash:"SHA-256"},false,["sign","verify"])})()}return _sessionKey};var toB64url=bytes=>{const u8=new Uint8Array(bytes);let bin="";for(let i=0;i<u8.length;i++)bin+=String.fromCharCode(u8[i]);return btoa(bin).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")};var fromB64url=s=>{const b=s.replace(/-/g,"+").replace(/_/g,"/");const pad=b.length%4?"=".repeat(4-b.length%4):"";const bin=atob(b+pad);const out=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)out[i]=bin.charCodeAt(i);return out};var createSession=async()=>{const exp=Math.floor(Date.now()/1e3)+SESSION_TTL;const key=await sessionKey();const sig=await crypto.subtle.sign("HMAC",key,AUTH_ENC.encode(String(exp)));return`${exp}.${toB64url(sig)}`};var verifySession=async token=>{if(!token)return false;const dot=token.indexOf(".");if(dot<1)return false;const rawExp=token.slice(0,dot);if(!/^\d{1,12}$/.test(rawExp))return false;if(+rawExp<=Math.floor(Date.now()/1e3))return false;let sig;try{sig=fromB64url(token.slice(dot+1))}catch{return false}try{const key=await sessionKey();return await crypto.subtle.verify("HMAC",key,sig,AUTH_ENC.encode(rawExp))}catch{return false}};var readCookie=(req,name)=>{const raw=req.headers.get("Cookie")||"";for(const part of raw.split(";")){const i=part.indexOf("=");if(i<0)continue;if(part.slice(0,i).trim()===name)return part.slice(i+1).trim()}return""};var hasSession=req=>verifySession(readCookie(req,SESSION_COOKIE));var secureFlag=url=>url.protocol==="https:"?"; Secure":"";var sessionCookie=(token,url)=>`${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL}${secureFlag(url)}`;var clearCookie=url=>`${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secureFlag(url)}`;var authFailures=new Map;var pruneFailures=now=>{for(const[key,rec]of authFailures){if(now>=rec.reset)authFailures.delete(key)}};var authLimited=ip=>{pruneFailures(Date.now());const rec=authFailures.get(ip);return!!rec&&rec.count>=AUTH_LIMIT};var recordAuthFailure=ip=>{const now=Date.now();pruneFailures(now);const rec=authFailures.get(ip);if(!rec){authFailures.set(ip,{count:1,reset:now+AUTH_WINDOW})}else{rec.count++}};var clearAuthFailures=ip=>authFailures.delete(ip);var clientIp=req=>req.headers.get("CF-Connecting-IP")||"local";var authDelay=()=>new Promise(resolve=>setTimeout(resolve,AUTH_FAIL_DELAY));var _htmlPanel=null;var getPanelPage=async()=>{if(_htmlPanel)return _htmlPanel;const enc=await getEncryptedUuid();_htmlPanel=renderPanel(JSON.stringify(enc),JSON.stringify(PANEL_INNER_HTML));return _htmlPanel};var HTML_HEADERS={"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store","X-Robots-Tag":"noindex","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer"};var _htmlPanel2=null;var getPanel2=async()=>{if(_htmlPanel2)return _htmlPanel2;_htmlPanel2=renderPanel2(JSON.stringify(CFG.id));return _htmlPanel2};var AUTH_HEADERS={"Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer"};var FORM_TYPES=new Set(["application/x-www-form-urlencoded","multipart/form-data"]);var entryPath=next=>next==="2"?"/?2panel="+CFG.panelKey:"/?panel="+CFG.panelKey;var handleSignin=async(req,url)=>{const ip=clientIp(req);if(authLimited(ip)){return new Response(null,{status:429,headers:{...AUTH_HEADERS,"Retry-After":"600"}})}const ct=(req.headers.get("Content-Type")||"").split(";")[0].trim().toLowerCase();const isForm=FORM_TYPES.has(ct);let body=null;try{if(isForm){const fd=await req.formData();body={id:fd.get("id")||"",key:fd.get("key")||"",next:fd.get("next")||""}}else{body=await req.json()}}catch{body=null}const id=body&&typeof body==="object"?body.id:"";const key=body&&typeof body==="object"?body.key:"";const next=body&&typeof body==="object"?body.next:"";if(!credentialsMatch(id,key)){recordAuthFailure(ip);await authDelay();if(isForm)return renderSignin(next==="2"?"2":"1",true);return new Response(null,{status:401,headers:AUTH_HEADERS})}clearAuthFailures(ip);const token=await createSession();const headers={...AUTH_HEADERS,"Set-Cookie":sessionCookie(token,url)};return isForm?new Response(null,{status:303,headers:{...headers,Location:entryPath(next)}}):new Response(null,{status:204,headers})};var handleSignout=async url=>new Response(null,{status:204,headers:{...AUTH_HEADERS,"Set-Cookie":clearCookie(url)}});var index_default={async fetch(req){const url=new URL(req.url);if(req.method==="POST"&&url.pathname==="/auth")return handleSignin(req,url);if(req.method==="POST"&&url.pathname==="/auth/logout")return handleSignout(url);if(req.headers.get("Upgrade")?.toLowerCase()!=="websocket"){const isPanel2=url.searchParams.get("2panel")===CFG.panelKey;const isPanel1=url.searchParams.get("panel")===CFG.panelKey;if(isPanel1||isPanel2){if(req.method!=="GET"&&req.method!=="HEAD"){return new Response(null,{status:405,headers:{...AUTH_HEADERS,Allow:"GET, HEAD"}})}if(isPanel1){return new Response(await getPanelPage(),{status:200,headers:HTML_HEADERS})}if(!await hasSession(req))return renderSignin("2");return new Response(await getPanel2(),{status:200,headers:HTML_HEADERS})}const apiResponse=handleApi(req,url);if(apiResponse)return apiResponse;return handleWeb(req,url)}if(!CFG.pathPrefix.some(p=>url.pathname.startsWith(p))){return webNotFound(url)}const strategy=parseStrategy(url.searchParams);const[client,server]=Object.values(new WebSocketPair);server.accept({allowHalfOpen:true});server.binaryType="arraybuffer";runSession(server,req,strategy);return new Response(null,{status:101,webSocket:client,headers:{"Sec-WebSocket-Extensions":""}})}};export{index_default as default};
