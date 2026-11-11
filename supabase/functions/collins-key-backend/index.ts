import postgres from "npm:postgres@3.4.7";
const dbUrl=Deno.env.get("SUPABASE_DB_URL");if(!dbUrl)throw new Error("Banco indisponivel");
const sql=postgres(dbUrl,{prepare:false,max:1,idle_timeout:20,connect_timeout:10});
const json=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json","cache-control":"no-store"}});
const sha=async(x:string)=>Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(x))),b=>b.toString(16).padStart(2,"0")).join("");
Deno.serve(async(req:Request)=>{try{
 if(req.method!=="POST")return json({error:"method"},405);
 const supplied=req.headers.get("x-collins-backend")||"";if(supplied.length<32||supplied.length>256)return json({error:"unauthorized"},401);
 const rec=await sql`SELECT secret_hash FROM collins_private.service_secrets WHERE name='edge_backend'`;const hash=await sha(supplied);const expected=String(rec[0]?.secret_hash||"");let diff=hash.length^expected.length;for(let i=0;i<64;i++)diff|=(hash.charCodeAt(i)||0)^(expected.charCodeAt(i)||0);if(diff!==0)return json({error:"unauthorized"},401);
 const text=await req.text();if(text.length>4096)return json({error:"too large"},413);const body=JSON.parse(text), op=body.op;
 if(op==="health"){await sql`SELECT 1`;return json({ok:true})}
 if(op==="verify"){if(typeof body.keyHash!=="string"||!/^[0-9a-f]{64}$/.test(body.keyHash))return json({error:"invalid"},400);const r=await sql`SELECT 1 FROM collins_private.licenses WHERE key_hash=${body.keyHash} AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())`;return json({valid:r.length>0})}
 if(op==="create"){if(typeof body.keyHash!=="string"||!/^[0-9a-f]{64}$/.test(body.keyHash)||typeof body.label!=="string"||body.label.length>100||!Number.isInteger(body.days)||body.days<1||body.days>3650)return json({error:"invalid"},400);const r=await sql`INSERT INTO collins_private.licenses(key_hash,label,expires_at) VALUES(${body.keyHash},${body.label},now()+(${body.days} * interval '1 day')) RETURNING id,label,expires_at`;return json(r[0])}
 if(op==="list"){const r=await sql`SELECT id,label,created_at,expires_at,revoked_at FROM collins_private.licenses ORDER BY id DESC LIMIT 500`;return json(r)}
 if(op==="revoke"||op==="unban"){if(typeof body.id!=="string"||!/^\d{1,15}$/.test(body.id))return json({error:"invalid"},400);const r=op==="revoke"?await sql`UPDATE collins_private.licenses SET revoked_at=now() WHERE id=${body.id} AND revoked_at IS NULL RETURNING id`:await sql`UPDATE collins_private.licenses SET revoked_at=NULL WHERE id=${body.id} AND revoked_at IS NOT NULL RETURNING id`;return json({changed:r.length>0})}
 return json({error:"invalid"},400);
 }catch(e){console.error("collins backend failed",e instanceof Error?e.name:"error");return json({error:"backend indisponivel"},503)}});

