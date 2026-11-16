const crypto=require("node:crypto");
const {promisify}=require("node:util");
const {neon}=require("@neondatabase/serverless");
const scrypt=promisify(crypto.scrypt);
const send=(res,n,d)=>{res.statusCode=n;res.setHeader("Content-Type","application/json; charset=utf-8");res.setHeader("Cache-Control","no-store");res.end(JSON.stringify(d));};
async function body(req){if(req.body&&typeof req.body==="object")return req.body;let s="";for await(const c of req)s+=c;try{return JSON.parse(s||"{}")}catch{return {}}}
async function hash(v){const salt=crypto.randomBytes(16);const key=await scrypt(v,salt,64);return salt.toString("hex")+"$"+key.toString("hex")}
async function verify(v,h){const [s,k,...x]=String(h||"").split("$");if(x.length||!/^[a-f0-9]{32}$/i.test(s||"")||!/^[a-f0-9]{128}$/i.test(k||""))return false;const a=await scrypt(v,Buffer.from(s,"hex"),64),b=Buffer.from(k,"hex");return crypto.timingSafeEqual(a,b)}
const norm=v=>String(v||"").replace(/[^a-f0-9]/gi,"").toLowerCase();
const newCode=()=>crypto.randomBytes(16).toString("hex").toUpperCase().match(/.{1,4}/g).join("-");
const equal=(a,b)=>{if(!a||!b)return false;const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&crypto.timingSafeEqual(x,y)};
module.exports=async(req,res)=>{
 if(req.method!=="POST")return send(res,405,{ok:false,error:"method_not_allowed"});
 if(!process.env.DATABASE_URL)return send(res,503,{ok:false,error:"database_not_configured"});
 const b=await body(req),pin=String(b.pin||"");
 if(!/^[0-9]{6}$/.test(pin))return send(res,400,{ok:false,error:"pin_must_be_six_digits"});
 const sql=neon(process.env.DATABASE_URL);
 try{
  const users=await sql\`SELECT id,username,recovery_code_hash FROM app_users WHERE active=true AND is_admin=true ORDER BY created_at ASC LIMIT 1\`;
  if(!users.length)return send(res,404,{ok:false,error:"admin_not_found"});
  const u=users[0];
  if(b.action==="setup"){
   if(!equal(String(b.setupToken||""),process.env.ASIA_SETUP_TOKEN))return send(res,403,{ok:false,error:"setup_link_invalid"});
   if(u.recovery_code_hash)return send(res,409,{ok:false,error:"setup_already_completed"});
  }else if(b.action==="recover"){
   const rc=norm(b.recoveryCode);
   if(!/^[a-f0-9]{32}$/.test(rc)||!u.recovery_code_hash||!(await verify(rc,u.recovery_code_hash)))return send(res,401,{ok:false,error:"recovery_code_invalid"});
  }else return send(res,400,{ok:false,error:"unknown_action"});
  const pinHash=await hash(pin),code=newCode(),codeHash=await hash(norm(code));
  let changed;
  if(b.action==="setup")changed=await sql\`UPDATE app_users SET pin_hash=\${pinHash},recovery_code_hash=\${codeHash},recovery_code_used_at=NULL WHERE id=\${u.id} AND recovery_code_hash IS NULL RETURNING id\`;
  else changed=await sql\`UPDATE app_users SET pin_hash=\${pinHash},recovery_code_hash=\${codeHash},recovery_code_used_at=now() WHERE id=\${u.id} AND recovery_code_hash=\${u.recovery_code_hash} RETURNING id\`;
  if(!changed.length)return send(res,409,{ok:false,error:"code_already_used_or_setup_done"});
  await sql\`UPDATE auth_sessions SET revoked_at=now() WHERE user_id=\${u.id} AND revoked_at IS NULL\`;
  await sql\`DELETE FROM auth_attempts\`;
  return send(res,200,{ok:true,username:u.username,recoveryCode:code});
 }catch(e){console.error("Asia recovery error",e?.message||"unknown");return send(res,500,{ok:false,error:"server_error"})}
};