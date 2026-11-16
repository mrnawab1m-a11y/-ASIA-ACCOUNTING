const crypto = require("node:crypto");
const { neon } = require("@neondatabase/serverless");
const COOKIE = "asia_admin_session";
function send(res,status,data){res.statusCode=status;res.setHeader("Content-Type","application/json; charset=utf-8");res.setHeader("Cache-Control","no-store");res.end(JSON.stringify(data))}
function readCookie(header=""){for(const part of header.split(";")){const i=part.indexOf("=");if(i>0&&part.slice(0,i).trim()===COOKIE){try{return decodeURIComponent(part.slice(i+1).trim())}catch{return null}}}return null}
async function readBody(req){if(req.body&&typeof req.body==="object")return req.body;let raw="";for await(const chunk of req){raw+=chunk;if(raw.length>12000)throw new Error("large")}try{return JSON.parse(raw||"{}")}catch{return {}}}
const clean=v=>String(v??"").trim();
module.exports=async function(req,res){
 if(!["GET","POST"].includes(req.method))return send(res,405,{error:"method_not_allowed"});
 if(!process.env.DATABASE_URL)return send(res,503,{error:"database_not_configured"});
 const token=readCookie(req.headers.cookie||"");if(!token||!/^[a-f0-9]{64}$/i.test(token))return send(res,401,{error:"unauthorized"});
 if(req.method==="POST"){try{if(!req.headers.origin||!req.headers.host||new URL(req.headers.origin).host!==req.headers.host)return send(res,403,{error:"origin_not_allowed"})}catch{return send(res,403,{error:"origin_not_allowed"})}}
 const sql=neon(process.env.DATABASE_URL),hash=crypto.createHash("sha256").update(token).digest("hex");
 try{
  const sessions=await sql`SELECT u.workspace_id FROM auth_sessions s JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=${hash} AND s.revoked_at IS NULL AND s.expires_at>now() AND u.active=true AND u.is_admin=true LIMIT 1`;
  if(!sessions.length)return send(res,401,{error:"unauthorized"});
  const workspaceId=sessions[0].workspace_id;
  if(req.method==="GET"){const rows=await sql`SELECT c.id,c.name,c.phone,c.address,c.notes,c.created_at,COALESCE((SELECT SUM(s.total_amount*s.exchange_rate) FROM sales s WHERE s.customer_id=c.id AND s.workspace_id=c.workspace_id),0) AS total_sales_afn,COALESCE((SELECT SUM(p.amount*p.exchange_rate) FROM payments p WHERE p.customer_id=c.id AND p.workspace_id=c.workspace_id),0) AS paid_sales_afn,COALESCE((SELECT SUM(s.total_amount*s.exchange_rate) FROM sales s WHERE s.customer_id=c.id AND s.workspace_id=c.workspace_id),0)-COALESCE((SELECT SUM(p.amount*p.exchange_rate) FROM payments p WHERE p.customer_id=c.id AND p.workspace_id=c.workspace_id),0) AS balance_afn FROM customers c WHERE c.workspace_id=${workspaceId} ORDER BY c.created_at DESC LIMIT 300`;return send(res,200,{ok:true,customers:rows})}
  let input;try{input=await readBody(req)}catch{return send(res,413,{error:"request_too_large"})}
  const name=clean(input.name),phone=clean(input.phone),address=clean(input.address),notes=clean(input.notes);
  if(!name||name.length>160)return send(res,400,{error:"invalid_name"});
  if([phone,address,notes].some(v=>v.length>500))return send(res,400,{error:"field_too_long"});
  const rows=await sql`INSERT INTO customers(workspace_id,name,phone,address,notes) VALUES(${workspaceId},${name},${phone||null},${address||null},${notes||null}) RETURNING id,name,phone,address,notes,created_at`;
  return send(res,201,{ok:true,customer:rows[0]});
 }catch(error){console.error("Asia customers API error:",error?.message||"unknown");return send(res,500,{error:"server_error"})}
};