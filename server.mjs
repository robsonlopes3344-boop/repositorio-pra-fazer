import express from 'express';
import crypto from 'node:crypto';
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
app.post('/v1/verify',limit,async(req,res)=>{const key=req.body?.key;if(typeof key!=='string'||!/^COL-[A-Za-z0-9_-]{43}$/.test(key))return res.status(401).json({valid:false});try{const x=await backend({op:'verify',keyHash:hash(key)});res.status(x.valid?200:401).json({valid:x.valid===true})}catch{res.status(503).json({valid:false})}});
app.post('/v1/admin/keys',limit,authorized,async(req,res)=>{const days=req.body?.days??30,label=req.body?.label??'';if(!Number.isInteger(days)||days<1||days>3650||typeof label!=='string'||label.length>100)return res.status(400).json({error:'dados invalidos'});try{const key='COL-'+crypto.randomBytes(32).toString('base64url');const result=await backend({op:'create',keyHash:hash(key),label,days});res.status(201).json({...result,key})}catch{res.status(503).json({error:'banco indisponivel'})}});
app.get('/v1/admin/keys',limit,authorized,async(req,res)=>{try{const result=await backend({op:'list'});res.json(result)}catch{res.status(503).json({error:'banco indisponivel'})}});
app.post('/v1/admin/keys/:id/revoke',limit,authorized,async(req,res)=>{if(!/^\d{1,15}$/.test(req.params.id))return res.status(400).json({error:'id invalido'});try{const x=await backend({op:'revoke',id:req.params.id});res.status(x.changed?200:404).json({revoked:x.changed===true})}catch{res.status(503).json({error:'banco indisponivel'})}});
app.post('/v1/admin/keys/:id/unban',limit,authorized,async(req,res)=>{if(!/^\d{1,15}$/.test(req.params.id))return res.status(400).json({error:'id invalido'});try{const x=await backend({op:'unban',id:req.params.id});res.status(x.changed?200:404).json({unbanned:x.changed===true})}catch{res.status(503).json({error:'banco indisponivel'})}});
app.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('Servidor iniciado'));

