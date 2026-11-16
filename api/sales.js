const crypto = require("node:crypto");
const { neon } = require("@neondatabase/serverless");
const COOKIE = "asia_admin_session";
function send(res,status,data){res.statusCode=status;res.setHeader("Content-Type","application/json; charset=utf-8");res.setHeader("Cache-Control","no-store");res.end(JSON.stringify(data));}
function cookies(header=""){const out={};for(const part of header.split(";")){const i=part.indexOf("=");if(i>0){const k=part.slice(0,i).trim();try{out[k]=decodeURIComponent(part.slice(i+1).trim())}catch{}}}return out;}
async function bodyOf(req){if(req.body&&typeof req.body==="object")return req.body;let raw="";for await(const chunk of req){raw+=chunk;if(raw.length>30000)throw new Error("body_too_large")}try{return JSON.parse(raw||"{}")}catch{return {}}}
const clean=v=>String(v??"").trim();
module.exports=async function handler(req,res){
 if(!["GET","POST"].includes(req.method))return send(res,405,{ok:false,error:"method_not_allowed"});
 if(!process.env.DATABASE_URL)return send(res,503,{ok:false,error:"database_not_configured"});
 const token=cookies(req.headers.cookie||"")[COOKIE];
 if(!token||!/^[a-f0-9]{64}$/i.test(token))return send(res,401,{ok:false,error:"unauthorized"});
 if(req.method==="POST"){const origin=req.headers.origin,host=req.headers.host;try{if(!origin||!host||new URL(origin).host!==host)return send(res,403,{ok:false,error:"origin_not_allowed"})}catch{return send(res,403,{ok:false,error:"origin_not_allowed"})}}
 const tokenHash=crypto.createHash("sha256").update(token).digest("hex"),sql=neon(process.env.DATABASE_URL);
 try{
  const sessions=await sql`SELECT u.workspace_id FROM auth_sessions s JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=${tokenHash} AND s.revoked_at IS NULL AND s.expires_at>now() AND u.active=true AND u.is_admin=true LIMIT 1`;
  if(!sessions.length)return send(res,401,{ok:false,error:"unauthorized"});
  const workspaceId=sessions[0].workspace_id;
  if(req.method==="GET"){
   const rows=await sql`SELECT s.id,s.document_no,s.sold_at,s.currency,s.exchange_rate,s.total_amount,s.paid_amount,s.cost_amount,s.gross_profit,s.notes,c.name AS customer_name,COALESCE(json_agg(json_build_object('product_name',p.name,'quantity',si.quantity,'unit',si.unit,'unit_price',si.unit_price,'line_total',si.line_total,'line_cost',si.line_cost)) FILTER(WHERE si.id IS NOT NULL),'[]'::json) AS items FROM sales s LEFT JOIN customers c ON c.id=s.customer_id AND c.workspace_id=s.workspace_id LEFT JOIN sale_items si ON si.sale_id=s.id LEFT JOIN products p ON p.id=si.product_id WHERE s.workspace_id=${workspaceId} GROUP BY s.id,c.name ORDER BY s.sold_at DESC LIMIT 100`;
   return send(res,200,{ok:true,sales:rows});
  }
  let input;try{input=await bodyOf(req)}catch{return send(res,413,{ok:false,error:"request_too_large"})}
  const currency=clean(input.currency||"AFN"),rate=Number(input.exchange_rate),paid=Number(input.paid_amount||0),customerId=clean(input.customer_id)||null,notes=clean(input.notes);
  if(!["AFN","USD","PKR"].includes(currency)||!Number.isFinite(rate)||rate<=0||!Number.isFinite(paid)||paid<0||notes.length>1000||!Array.isArray(input.items)||!input.items.length||input.items.length>50)return send(res,400,{ok:false,error:"invalid_sale"});
  const items=[];
  for(const x of input.items){const product_id=clean(x.product_id),quantity=Number(x.quantity),unit_price=Number(x.unit_price);if(!/^[0-9a-f-]{36}$/i.test(product_id)||!Number.isFinite(quantity)||quantity<=0||!Number.isFinite(unit_price)||unit_price<0)return send(res,400,{ok:false,error:"invalid_item"});items.push({product_id,quantity,unit_price})}
  const result=await sql`SELECT register_asia_sale(${workspaceId}::uuid,${customerId}::uuid,${currency},${rate},${paid},${notes},${JSON.stringify(items)}::jsonb) AS sale`;
  return send(res,201,{ok:true,sale:result[0].sale});
 }catch(error){
  const msg=String(error?.message||"");
  const known=["invalid_sale","invalid_item","invalid_paid_amount","customer_not_found","product_not_found"];
  if(known.some(x=>msg.includes(x)))return send(res,400,{ok:false,error:known.find(x=>msg.includes(x))});
  if(msg.includes("insufficient_stock"))return send(res,409,{ok:false,error:"insufficient_stock"});
  console.error("Asia sales API error:",msg.slice(0,300));return send(res,500,{ok:false,error:"server_error"});
 }
};