const crypto=require("node:crypto");
const {neon}=require("@neondatabase/serverless");
const COOKIE="asia_admin_session";
function send(res,status,data){res.statusCode=status;res.setHeader("Content-Type","application/json; charset=utf-8");res.setHeader("Cache-Control","no-store");res.end(JSON.stringify(data))}
function readCookie(header=""){for(const part of header.split(";")){const i=part.indexOf("=");if(i>0&&part.slice(0,i).trim()===COOKIE){try{return decodeURIComponent(part.slice(i+1).trim())}catch{return null}}}return null}
async function readBody(req){if(req.body&&typeof req.body==="object")return req.body;let raw="";for await(const chunk of req){raw+=chunk;if(raw.length>4500000)throw new Error("large")}try{return JSON.parse(raw||"{}")}catch{return null}}
module.exports=async function(req,res){
 if(req.method!=="POST")return send(res,405,{ok:false,error:"method_not_allowed"});
 if(!process.env.DATABASE_URL)return send(res,503,{ok:false,error:"database_not_configured"});
 const token=readCookie(req.headers.cookie||"");if(!token||!/^[a-f0-9]{64}$/i.test(token))return send(res,401,{ok:false,error:"unauthorized"});
 try{if(!req.headers.origin||!req.headers.host||new URL(req.headers.origin).host!==req.headers.host)return send(res,403,{ok:false,error:"origin_not_allowed"})}catch{return send(res,403,{ok:false,error:"origin_not_allowed"})}
 const sql=neon(process.env.DATABASE_URL),hash=crypto.createHash("sha256").update(token).digest("hex");
 try{
  const sessions=await sql`SELECT u.workspace_id FROM auth_sessions s JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=${hash} AND s.revoked_at IS NULL AND s.expires_at>now() AND u.active=true AND u.is_admin=true LIMIT 1`;
  if(!sessions.length)return send(res,401,{ok:false,error:"unauthorized"});
  const wid=String(sessions[0].workspace_id);
  let backup;try{backup=await readBody(req)}catch{return send(res,413,{ok:false,error:"backup_too_large"})}
  if(!backup||backup.format!=="asia-accounting-backup"||backup.version!==1||backup.workspace_id!==wid||!backup.data||typeof backup.data!=="object")return send(res,400,{ok:false,error:"backup_not_for_this_account"});
  const keys=["products","customers","suppliers","purchases","sales","purchase_items","sale_items","stock_movements","stock_cost_layers","payments","exchange_rates","expenses","machine_income","app_settings"];
  for(const key of keys){const rows=backup.data[key]??[];if(!Array.isArray(rows)||rows.length>50000)return send(res,400,{ok:false,error:"invalid_backup"});if(rows.some(row=>!row||typeof row!=="object"||(row.workspace_id!==undefined&&String(row.workspace_id)!==wid)))return send(res,400,{ok:false,error:"backup_workspace_mismatch"})}
  const statements=[
   sql`INSERT INTO products SELECT (jsonb_populate_record(NULL::public.products,v)).* FROM jsonb_array_elements(${JSON.stringify(backup.data.products||[])}::jsonb) AS x(v) ON CONFLICT DO NOTHING RETURNING id`,
   sql`INSERT INTO customers SELECT (jsonb_populate_record(NULL::public.customers,v)).* FROM jsonb_array_elements(${JSON.stringify(backup.data.customers||[])}::jsonb) AS x(v) ON CONFLICT DO NOTHING RETURNING id`,
   sql`INSERT INTO suppliers SELECT (jsonb_populate_record(NULL::public.suppliers,v)).* FROM jsonb_array_elements(${JSON.stringify(backup.data.suppliers||[])}::jsonb) AS x(v) ON CONFLICT DO NOTHING RETURNING id`,
   sql`INSERT INTO purchases SELECT (jsonb_populate_record(NULL::public.purchases,v)).* FROM jsonb_array_elements(${JSON.stringify(backup.data.purchases||[])}::jsonb) AS x(v) ON CONFLICT DO NOTHING RETURNING id`,
   sql`INSERT INTO sales SELECT (jsonb_populate_record(NULL::public.sales,v)).* FROM jsonb_array_elements(${JSON.stringify(backup.data.sales||[])}::jsonb) AS x(v) ON CONFLICT DO NOTHING RETURNING id`,
   sql`INSERT INTO purchase_items SELECT (jsonb_populate_record(NULL::public.purchase_items,v)).* FROM jsonb_array_elements(${JSON.stringify(backup.data.purchase_items||[])}::jsonb) AS x(v) ON CONFLICT DO NOTHING RETURNING id`,
   sql`INSERT INTO sale_items SELECT (jsonb_populate_record(NULL::public.sale_items,v)).* FROM jsonb_array_elements(${JSON.stringify(backup.data.sale_items||[])}::jsonb) AS x(v) ON CONFLICT DO NOTHING RETURNING id`,
   sql`INSERT INTO stock_movements SELECT (jsonb_populate_record(NULL::public.stock_movements,v)).* FROM jsonb_array_elements(${JSON.stringify(backup.data.stock_movements||[])}::jsonb) AS x(v) ON CONFLICT DO NOTHING RETURNING id`,
   sql`INSERT INTO stock_cost_layers SELECT (jsonb_populate_record(NULL::public.stock_cost_layers,v)).* FROM jsonb_array_elements(${JSON.stringify(backup.data.stock_cost_layers||[])}::jsonb) AS x(v) ON CONFLICT DO NOTHING RETURNING id`,
   sql`INSERT INTO payments SELECT (jsonb_populate_record(NULL::public.payments,v)).* FROM jsonb_array_elements(${JSON.stringify(backup.data.payments||[])}::jsonb) AS x(v) ON CONFLICT DO NOTHING RETURNING id`,
   sql`INSERT INTO exchange_rates SELECT (jsonb_populate_record(NULL::public.exchange_rates,v)).* FROM jsonb_array_elements(${JSON.stringify(backup.data.exchange_rates||[])}::jsonb) AS x(v) ON CONFLICT DO NOTHING RETURNING id`,
   sql`INSERT INTO expenses SELECT (jsonb_populate_record(NULL::public.expenses,v)).* FROM jsonb_array_elements(${JSON.stringify(backup.data.expenses||[])}::jsonb) AS x(v) ON CONFLICT DO NOTHING RETURNING id`,
   sql`INSERT INTO machine_income SELECT (jsonb_populate_record(NULL::public.machine_income,v)).* FROM jsonb_array_elements(${JSON.stringify(backup.data.machine_income||[])}::jsonb) AS x(v) ON CONFLICT DO NOTHING RETURNING id`,
   sql`INSERT INTO app_settings SELECT (jsonb_populate_record(NULL::public.app_settings,v)).* FROM jsonb_array_elements(${JSON.stringify(backup.data.app_settings||[])}::jsonb) AS x(v) ON CONFLICT DO NOTHING RETURNING workspace_id`
  ];
  const results=await sql.transaction(statements);
  const restored=Object.fromEntries(keys.map((key,i)=>[key,Array.isArray(results[i])?results[i].length:0]));
  return send(res,200,{ok:true,restored,message:"missing_records_restored_without_overwriting_existing"});
 }catch(error){console.error("Asia restore API error:",error?.message||"unknown");return send(res,400,{ok:false,error:"restore_failed_check_backup"})}
};
