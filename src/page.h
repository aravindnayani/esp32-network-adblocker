#pragma once
// Dashboard HTML for the C3 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>C3 AdBlock</title><style>
body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d}
h1{margin:0;font-size:18px}h1 span{color:#3fb950}.wrap{padding:16px;max-width:1000px;margin:auto}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:18px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
th{background:#21262d;color:#8b949e}tr:hover td{background:#1c2128}
.b{color:#f85149}.a{color:#3fb950}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:4px 9px;cursor:pointer}
button:hover{background:#30363d}.ban{color:#f85149}input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
h2{font-size:14px;color:#8b949e;margin:18px 0 8px}
</style></head><body>
<header><h1>🛡️ C3 AdBlock <span id=host></span></h1></header><div class=wrap>
<div id=credwarn style="display:none;background:#3b1d1d;border:1px solid #f85149;color:#ffb3ae;border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px">
⚠️ <b>No admin password set.</b> Settings, uploads and firmware updates are locked. To set one, hold the <b>BOOT</b> button while powering the device on, then join its <code>C3-AdBlock-XXXX</code> WiFi (password on the serial console) and fill in the setup page.
</div>
<div id=glock style="display:none;margin-bottom:10px;padding:10px 14px;background:#3b1d1d;border:1px solid #f85149;color:#ffb3ae;border-radius:8px;font-size:13px"></div>
<div id=loginbar style="display:none;align-items:center;gap:12px;margin-bottom:14px;padding:12px 14px;background:#161b22;border:1px solid #30363d;border-radius:8px">
<span style=flex:1>🔒 Log in to see clients, custom domains, settings and the audit log. <span id=lockmsg class=b></span></span><button onclick=login()>Log in</button></div>
<div id=blockbar style="display:flex;align-items:center;gap:12px;margin-bottom:14px;padding:12px 14px;background:#161b22;border:1px solid #30363d;border-radius:8px">
<span id=blockdot style=font-size:20px>🛡️</span><b id=blockstate style=flex:1 data-on=1>Blocking active</b>
<select id=pausedur style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:5px"><option value=30>30s</option><option value=300 selected>5 min</option><option value=900>15 min</option><option value=3600>1 hour</option><option value=0>until I re-enable</option></select>
<button id=pausebtn onclick=togglePause()>Pause</button></div>
<div id=confbar style="display:none;margin-bottom:14px;padding:12px 14px;background:#2d2410;border:1px solid #d29922;color:#f2cc60;border-radius:8px">
👆 <b>Press the BOOT button on the device</b> to approve <b id=confwhat></b> <span id=confleft style=color:#8b949e></span></div>
<div id=upwarn style="display:none;background:#3b1d1d;border:1px solid #f85149;color:#ffb3ae;border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px"></div>
<div class=cards id=sys></div>
<div id=upstat style="color:#8b949e;font-size:12px;margin:-6px 0 14px"></div>
<div id=admin style=display:none>
<h2>CLIENTS</h2><table id=ct><thead><tr><th>Client</th><th>MAC</th><th>Blocked</th><th>Allowed</th><th></th></tr></thead><tbody></tbody></table>
<h2>CUSTOM BLOCKED DOMAINS</h2>
<div style=margin-bottom:8px><input id=dom placeholder="ads.example.com" size=30><button onclick=addDom()>Block domain</button></div>
<table id=cl><tbody></tbody></table>
<h2>BLOCKLIST &mdash; UPLOAD</h2>
<form id=upf style=margin-bottom:6px><input type=file id=blf accept=.bin><button>Upload blocklist</button> <span id=upmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">build <code>blocklist.bin</code> with <code>tools/build_blocklist.py</code>, then upload here &mdash; no USB</div>
<h2>BLOCKLIST &mdash; REMOTE AUTO-UPDATE</h2>
<div style=margin-bottom:6px><input id=uurl type=url pattern="https://.*" placeholder="https://host/blocklist.bin" size=40> every <input id=uiv type=number min=1 max=720 style=width:4.5em value=24>h
<button onclick=saveUpd()>Save</button> <button onclick=fetchNow()>Fetch now</button></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">device pulls a prebuilt <code>blocklist.bin</code> on a schedule (e.g. a GitHub release asset). last: <span id=ustat>&mdash;</span></div>
<h2>FIRMWARE &mdash; OTA UPDATE</h2>
<form id=fwf style=margin-bottom:6px><input type=file id=fwb accept=.bin><button>Flash firmware</button> <span id=fwmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">upload <code>.pio/build/c3/firmware.bin</code> &mdash; device verifies it and reboots into it</div>
<h2>WIFI</h2>
<div style=margin-bottom:18px><button onclick="if(confirm('Forget saved WiFi and reboot into the setup portal?'))forgetWifi()">Forget WiFi</button></div>
<h2>SECURITY</h2>
<div style=margin-bottom:6px><label><input type=checkbox id=physcb onchange=setPhys()> Require a BOOT button press for firmware/blocklist uploads, a new update URL, Forget WiFi and pausing for more than 15 min an hour</label></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:12px">stops software that has your password (a browser agent, a script) from changing these on its own. With it on, network OTA (<code>pio run -t upload</code>) only works for 60 s after you press BOOT. <span id=otawin></span></div>
<table id=lt><thead><tr><th>Locked out</th><th>MAC</th><th>Wrong passwords</th><th>Status</th></tr></thead><tbody></tbody></table>
<table id=at><thead><tr><th>When</th><th>From</th><th>Event</th><th>Detail</th></tr></thead><tbody></tbody></table>
</div></div><script>
function fmt(n){return n.toLocaleString()}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
// A plain <img>/<form> CSRF can't set a custom header, only same-origin fetch()
// can — so requiring this on every mutating request blocks drive-by CSRF even
// though the server can't otherwise tell a forged request from a real one over
// HTTP Basic Auth (browsers auto-replay cached Basic Auth cross-origin).
const CSRF_HDRS={'X-Requested-With':'c3-adblock'}
// With physical confirmation on, pauses beyond the free 15 min/hour (or indefinite) need a press.
async function togglePause(){if(blockstate.dataset.on!='1'){fetch('/resume',{headers:CSRF_HDRS}).then(load);return}
let v=pausedur.value,u='/pause?s='+v;
if(physOn&&(v=='0'||+v>pauseFree)&&!await gated('pause',v))return;
let r=await fetch(u,{headers:CSRF_HDRS});
if(r.status==428&&await gated('pause',v))r=await fetch(u,{headers:CSRF_HDRS});
if(!r.ok)alert(await r.text());load()}
let physOn=false,pauseFree=0;
// The summary is public; everything else in /stats.json only comes back when logged in.
async function login(){let r=await fetch('/login',{headers:CSRF_HDRS});if(!r.ok)alert(await r.text());load()}
async function load(){let s=await(await fetch('/stats.json',{headers:CSRF_HDRS})).json();
host.textContent='@ '+s.ip;
credwarn.style.display=s.noauth?'block':'none';
let on=s.blocking!==false;blockstate.dataset.on=on?'1':'0';
blockdot.textContent=on?'🛡️':'⏸️';blockbar.style.borderColor=on?'#30363d':'#f0883e';
blockstate.textContent=on?'Blocking active':(s.resumeIn>0?'Paused — resumes in '+s.resumeIn+'s':'Paused');
pausebtn.textContent=on?'Pause':'Resume';pausebtn.style.display=s.admin?'':'none';pausedur.style.display=on&&s.admin?'':'none';
sys.innerHTML=[['Total blocked',fmt(s.blocked),'b'],['Total allowed',fmt(s.allowed),'a'],...(s.foreign?[['Dropped (non-local)',fmt(s.foreign),'b']]:[]),['Blocklist',fmt(s.domains)+' domains',''],
['Clients',s.nclients,''],['WiFi',s.rssi+' dBm',''],['Temp',s.temp+' °C',''],['Free RAM',Math.round(s.heap/1024)+' KB',''],['Uptime',s.uptime,'']]
.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${c[0]}</div></div>`).join('');
let upDown=/^(DOWN|UNENCRYPTED)/.test(s.upstream||'');upwarn.style.display=upDown?'block':'none';upwarn.textContent=upDown?'⚠️ Upstream DNS: '+s.upstream:'';upstat.textContent=upDown?'':'🔒 Upstream DNS: '+(s.upstream||'');
glock.style.display=s.globalLock?'block':'none';glock.textContent=s.globalLock?'⛔ Too many wrong passwords across the network: every device is refused for '+s.globalLock+'s. Press BOOT on the device to clear it.':'';
loginbar.style.display=s.admin||s.noauth?'none':'flex';lockmsg.textContent=s.locked?'Locked for '+s.locked+'s after wrong passwords.':'';
admin.style.display=s.admin?'':'none';if(!s.admin){showConf(null);return}
ct.tBodies[0].innerHTML=s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
`<tr><td>${c.ip}${c.banned?' <span class=tag style=color:#f85149>BANNED</span>':''}</td><td>${c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td>
<td><button class=ban data-ip="${esc(c.ip)}" data-mac="${esc(c.mac)}">${c.banned?'Unban':'Ban'}</button></td></tr>`).join('');
cl.tBodies[0].innerHTML=s.custom.map(d=>`<tr><td>${esc(d)}</td><td style=text-align:right><button class=rmbtn data-d="${esc(d)}">remove</button></td></tr>`).join('')||'<tr><td style=color:#8b949e>none yet</td></tr>';
physcb.checked=physOn=!!s.phys;pauseFree=s.pauseFree||0;otawin.textContent=s.otaWin?'Network OTA open for '+s.otaWin+'s.':'';
showConf(s.confirm);
lt.style.display=s.lockouts.length?'':'none';
lt.tBodies[0].innerHTML=s.lockouts.map(l=>`<tr><td>${esc(l.ip)}</td><td>${esc(l.mac)}</td><td class=b>${l.fails}</td><td>${l.lockedFor?'<span class=b>locked, '+l.lockedFor+'s left</span>':'not locked yet'}</td></tr>`).join('');
at.tBodies[0].innerHTML=s.audit.map(a=>`<tr><td>${ago(a.ago)}</td><td>${esc(a.ip)}${a.mac?'<br><span style=color:#8b949e>'+esc(a.mac)+'</span>':''}</td><td>${esc(a.what)}</td><td>${esc(a.detail)}</td></tr>`).join('')||'<tr><td colspan=4 style=color:#8b949e>no admin activity since boot</td></tr>';
upurlNow=s.upurl||'';
if(document.activeElement!=uurl)uurl.value=s.upurl||'';
if(document.activeElement!=uiv)uiv.value=s.upiv||24;
ustat.textContent=s.upstat||'—';}
function ago(t){return t<60?t+'s ago':t<3600?Math.floor(t/60)+'m ago':t<86400?Math.floor(t/3600)+'h ago':Math.floor(t/86400)+'d ago'}
const ACTS={update:'flashing firmware',upload:'uploading a blocklist',setupdate:'changing the update URL',forgetwifi:'forgetting WiFi',phys:'turning off physical confirmation',pause:'pausing blocking'};
function dur(s){return s<60?s+' s':s<3600?Math.round(s/60)+' min':Math.round(s/3600)+' h'}
function confDesc(c){let d=ACTS[c.a]||c.a,p=c.p||'';
if(c.a=='pause')d+=p=='0'?' until re-enabled':' for '+dur(+p);
else if(c.a=='setupdate')d+=' to '+(p||'(none)');
else if(/^\d+:[0-9a-f]{8}$/.test(p)){let[n,h]=p.split(':');d+=' ('+(n/1048576).toFixed(2)+' MB, checksum '+h+')'}
return d}
function showConf(c){confbar.style.display=c&&c.state=='pending'?'block':'none';
if(c){confwhat.textContent=confDesc(c)+' (requested by '+c.ip+')';confleft.textContent=c.left+'s left'}}
// 32-bit FNV-1a, as on the device: an approval is bound to fnv(param), and uploads to "<size>:<fnv of the file>".
function fnv(b,h=0x811c9dc5){for(let i=0;i<b.length;i++)h=Math.imul(h^b[i],16777619);return h>>>0}
function hex8(h){return h.toString(16).padStart(8,'0')}
async function fileTag(f){return f.size+':'+hex8(fnv(new Uint8Array(await f.arrayBuffer())))}
let upurlNow='';
// Ask the device for a BOOT-button approval of action `a` with parameter `p`, then wait for
// the press (or the timeout). Resolves true once approved; the next request for that action
// with that exact parameter uses the approval up.
async function gated(a,p=''){let q='/confirm?a='+a+'&p='+encodeURIComponent(p),r=await fetch(q,{headers:CSRF_HDRS}),t=await r.text();
if(r.status==409&&t.startsWith('this device')&&confirm(t+'\n\nCancel that request and ask again?')){
await fetch('/confirm?cancel=1',{headers:CSRF_HDRS});r=await fetch(q,{headers:CSRF_HDRS});t=await r.text()}
if(!r.ok){alert(t);return false}if(t=='approved')return true;
let want=hex8(fnv(new TextEncoder().encode(p)));
for(let i=0;i<40;i++){await new Promise(z=>setTimeout(z,800));
let c=(await(await fetch('/stats.json',{headers:CSRF_HDRS})).json()).confirm;showConf(c);
if(!c||c.a!=a){alert('Not confirmed: the BOOT button was not pressed in time.');return false}
if(c.ph!=want){alert('Your request was cancelled and replaced by another one: '+confDesc(c)+'. Check the audit log.');return false}
if(c.state=='approved'){showConf(null);return true}}
return false}
async function setPhys(){let on=physcb.checked;if(!on&&!await gated('phys')){physcb.checked=true;return}
let r=await fetch('/setphys?on='+(on?1:0),{headers:CSRF_HDRS});if(!r.ok)alert(await r.text());load()}
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(async r=>{if(r.ok)dom.value='';else alert(await r.text());load()})}}
ct.addEventListener('click',e=>{if(e.target.classList.contains('ban'))fetch('/ban?ip='+encodeURIComponent(e.target.dataset.ip)+'&mac='+encodeURIComponent(e.target.dataset.mac),{headers:CSRF_HDRS}).then(async r=>{if(!r.ok)alert(await r.text());load()})});
cl.addEventListener('click',e=>{if(e.target.classList.contains('rmbtn'))fetch('/unblock?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
async function saveUpd(){if(uurl.value.trim()!=upurlNow&&!await gated('setupdate',uurl.value.trim()))return;fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||24),{headers:CSRF_HDRS}).then(async r=>{if(!r.ok)alert(await r.text());load()})}
function fetchNow(){ustat.textContent='fetching...';fetch('/fetchnow',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>{ustat.textContent=t;load()})}
async function forgetWifi(){if(!await gated('forgetwifi'))return;fetch('/forgetwifi',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>alert(t))}
fwf.onsubmit=async e=>{e.preventDefault();let f=fwb.files[0];if(!f)return;fwmsg.textContent='waiting for BOOT press...';if(!await gated('update',await fileTag(f))){fwmsg.textContent='';return}fwmsg.textContent='flashing '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/update',{method:'POST',headers:CSRF_HDRS,body:fd});fwmsg.textContent=r.ok?'✓ rebooting, reconnect in ~15s':'✗ '+await r.text();}
catch(_){fwmsg.textContent='✓ rebooting, reconnect in ~15s';}};
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;upmsg.textContent='waiting for BOOT press...';if(!await gated('upload',await fileTag(f))){upmsg.textContent='';return}
upmsg.textContent='uploading '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/upload',{method:'POST',headers:CSRF_HDRS,body:fd});upmsg.textContent=(r.ok?'✓ ':'✗ ')+await r.text();}
catch(_){upmsg.textContent='✗ upload failed';}
blf.value='';setTimeout(load,600);};
load();setInterval(load,3000);
</script></body></html>)HTML";
