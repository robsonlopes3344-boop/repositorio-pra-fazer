import express from 'express';
import crypto from 'node:crypto';
import {promisify} from 'node:util';
const scrypt=promisify(crypto.scrypt);
import {fileURLToPath} from 'node:url';
const admin=process.env.ADMIN_TOKEN||'', edgeUrl=process.env.EDGE_URL||'', edgeSecret=process.env.EDGE_SECRET||'';
if(admin.length<32||edgeSecret.length<32||!edgeUrl.startsWith('https://'))throw Error('Configure ADMIN_TOKEN, EDGE_URL e EDGE_SECRET.');
async function backend(payload){const res=await fetch(edgeUrl,{method:'POST',headers:{'content-type':'application/json','x-collins-backend':edgeSecret},body:JSON.stringify(payload),signal:AbortSignal.timeout(15000)});if(!res.ok)throw Error('backend indisponivel');return await res.json();}
const app=express();app.disable('x-powered-by');app.set('trust proxy',1);app.use(express.json({limit:'4kb'}));
app.use((req,res,next)=>{res.set('Cache-Control','no-store');res.set('X-Content-Type-Options','nosniff');res.set('Content-Security-Policy',"default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");next()});
app.get('/admin',(req,res)=>res.sendFile(fileURLToPath(new URL('./admin.html',import.meta.url))));
app.get('/admin.js',(req,res)=>res.sendFile(fileURLToPath(new URL('./admin.js',import.meta.url))));
app.get('/admin.css',(req,res)=>res.sendFile(fileURLToPath(new URL('./admin.css',import.meta.url))));
const attempts=new Map();setInterval(()=>{const now=Date.now();for(const [k,v] of attempts)if(now>v.end)attempts.delete(k)},60000).unref();
function limit(req,res,next){const k=req.ip||'unknown',now=Date.now();let v=attempts.get(k);if(!v||now>v.end)v={n:0,end:now+60000};attempts.set(k,v);if(++v.n>30)return res.status(429).json({error:'limite'});next();}
function authorized(req,res,next){const x=Buffer.from(req.get('authorization')||''),y=Buffer.from('Bearer '+admin);if(x.length!==y.length||!crypto.timingSafeEqual(x,y))return res.status(401).json({error:'nao autorizado'});next();}
const hash=k=>crypto.createHash('sha256').update(k).digest('hex');
app.get('/health',async(req,res)=>{try{await backend({op:'health'});res.json({ok:true})}catch{res.status(503).json({ok:false})}});
app.post('/v1/verify',limit,(_req,res)=>res.status(410).json({valid:false,error:'Use login e cadastro.'}));
const validUser=u=>typeof u==='string'&&/^[a-z0-9_]{4,24}$/.test(u);
const validDevice=d=>typeof d==='string'&&/^[0-9a-f]{64}$/.test(d);
const validPassword=p=>typeof p==='string'&&Buffer.byteLength(p,'utf8')>=8&&Buffer.byteLength(p,'utf8')<=128;
async function makePassword(p){const salt=crypto.randomBytes(16);const value=await scrypt(p,salt,64);return 'scrypt$'+salt.toString('hex')+'$'+value.toString('hex');}
async function checkPassword(p,encoded){const x=(encoded||'').split('$');if(x.length!==3||x[0]!=='scrypt'||!/^[a-f0-9]{32}$/.test(x[1])||!/^[a-f0-9]{128}$/.test(x[2]))return false;const v=await scrypt(p,Buffer.from(x[1],'hex'),64);return crypto.timingSafeEqual(v,Buffer.from(x[2],'hex'));}
function issueSession(username,deviceHash){const payload=Buffer.from(JSON.stringify({u:username,d:deviceHash,exp:Date.now()+300000})).toString('base64url');return payload+'.'+crypto.createHmac('sha256',admin).update(payload).digest('base64url');}
function parseSession(token){try{if(typeof token!=='string'||token.length>1024)return null;const parts=token.split('.');if(parts.length!==2)return null;const a=Buffer.from(parts[1]),b=Buffer.from(crypto.createHmac('sha256',admin).update(parts[0]).digest('base64url'));if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return null;const o=JSON.parse(Buffer.from(parts[0],'base64url').toString('utf8'));return validUser(o.u)&&validDevice(o.d)&&Number.isFinite(o.exp)&&o.exp>Date.now()?o:null;}catch{return null;}}
app.post('/v1/register',limit,async(req,res)=>{const u=String(req.body?.username||'').toLowerCase(),p=req.body?.password,k=req.body?.key,d=req.body?.device;if(!validUser(u)||!validPassword(p)||typeof k!=='string'||!/^COL-[A-Za-z0-9_-]{43}$/.test(k)||!validDevice(d))return res.status(400).json({ok:false});try{const pw=await makePassword(p);const x=await backend({op:'register',username:u,passwordHash:pw,keyHash:hash(k),deviceHash:d});return res.status(x.created?201:409).json({ok:x.created===true})}catch{return res.status(503).json({ok:false})}});
app.post('/v1/login',limit,async(req,res)=>{const u=String(req.body?.username||'').toLowerCase(),p=req.body?.password,d=req.body?.device;if(!validUser(u)||!validPassword(p)||!validDevice(d))return res.status(401).json({ok:false});try{const result=await backend({op:'account',username:u});const a=result.account;if(!a||!await checkPassword(p,a.password_hash))return res.status(401).json({ok:false});const x=await backend({op:'bindDevice',username:u,deviceHash:d});if(!x.bound)return res.status(401).json({ok:false});return res.json({ok:true,session:issueSession(u,d)})}catch{return res.status(503).json({ok:false})}});
app.post('/v1/session/verify',limit,async(req,res)=>{const a=parseSession(req.body?.session);if(!a)return res.status(401).json({valid:false});try{const x=await backend({op:'session',username:a.u,deviceHash:a.d});return res.status(x.valid?200:401).json({valid:x.valid===true})}catch{return res.status(503).json({valid:false})}});
app.post('/v1/admin/keys/:id/reset-device',limit,authorized,async(req,res)=>{if(!/^\d{1,15}$/.test(req.params.id))return res.status(400).json({error:'id invalido'});try{const x=await backend({op:'resetDevice',id:req.params.id});return res.status(x.changed?200:404).json({reset:x.changed===true})}catch{return res.status(503).json({error:'banco indisponivel'})}});
app.post('/v1/admin/keys',limit,authorized,async(req,res)=>{const days=req.body?.days??30,label=req.body?.label??'';if(!Number.isInteger(days)||days<1||days>3650||typeof label!=='string'||label.length>100)return res.status(400).json({error:'dados invalidos'});try{const key='COL-'+crypto.randomBytes(32).toString('base64url');const result=await backend({op:'create',keyHash:hash(key),label,days});res.status(201).json({...result,key})}catch{res.status(503).json({error:'banco indisponivel'})}});
app.get('/v1/admin/keys',limit,authorized,async(req,res)=>{try{const result=await backend({op:'list'});res.json(result)}catch{res.status(503).json({error:'banco indisponivel'})}});
app.post('/v1/admin/keys/:id/revoke',limit,authorized,async(req,res)=>{if(!/^\d{1,15}$/.test(req.params.id))return res.status(400).json({error:'id invalido'});try{const x=await backend({op:'revoke',id:req.params.id});res.status(x.changed?200:404).json({revoked:x.changed===true})}catch{res.status(503).json({error:'banco indisponivel'})}});
app.post('/v1/admin/keys/:id/unban',limit,authorized,async(req,res)=>{if(!/^\d{1,15}$/.test(req.params.id))return res.status(400).json({error:'id invalido'});try{const x=await backend({op:'unban',id:req.params.id});res.status(x.changed?200:404).json({unbanned:x.changed===true})}catch{res.status(503).json({error:'banco indisponivel'})}});
app.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('Servidor iniciado'));

