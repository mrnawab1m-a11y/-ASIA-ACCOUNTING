const crypto = require("node:crypto");
const { neon } = require("@neondatabase/serverless");
const COOKIE = "asia_admin_session";
function send(res,status,data){res.statusCode=status;res.setHeader("Content-Type","application/json; charset=utf-8");res.setHeader("Cache-Control","no-store");res.end(JSON.stringify(data))}
function readCookie(header=""){for(const part of header.split(";")){const i=part.indexOf("=");if(i>0&&part.slice(0,i).trim()===COOKIE){try{return decodeURIComponent(part.slice(i+1).trim())}catch{return null}}}return null}
async function readBody(req){if(req.body&&typeof req.body==="object")return req.body;let raw="";for await(const chunk of req){raw+=chunk;if(raw.length>20000)throw new Error("large")}try{return JSON.parse(raw||"{}")}catch{return {}}}
const clean=v=>String(v??"").trim();
const amount=v=>{const n=Number(v);return Number.isFinite(n)?n:NaN};
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
  if(req.method==="GET"){
   const rows=await sql`SELECT p.id,p.document_no,p.purchased_at,p.currency,p.exchange_rate,p.total_amount,p.paid_amount,p.notes,s.name AS supplier_name,
    COUNT(pi.id)::int AS item_count
    FROM purchases p LEFT JOIN suppliers s ON s.id=p.supplier_id
    LEFT JOIN purchase_items pi ON pi.purchase_id=p.id
    WHERE p.workspace_id=${workspaceId}
    GROUP BY p.id,s.name ORDER BY p.purchased_at DESC LIMIT 100`;
   return send(res,200,{ok:true,purchases:rows});
  }
  let input;try{input=await readBody(req)}catch{return send(res,413,{error:"request_too_large"})}
  const supplierId=clean(input.supplier_id),currency=clean(input.currency),rate=amount(input.exchange_rate),paid=amount(input.paid_amount??0);
  const allowed=["AFN","USD","PKR"];
  if(!/^[0-9a-f-]{36}$/i.test(supplierId)||!allowed.includes(currency)||!Number.isFinite(rate)||rate<=0||rate>1000000||!Number.isFinite(paid)||paid<0)return send(res,400,{error:"invalid_purchase_details"});
  if(currency==="AFN"&&rate!==1)return send(res,400,{error:"afn_rate_must_be_one"});
  const supplier=await sql`SELECT id FROM suppliers WHERE id=${supplierId} AND workspace_id=${workspaceId} LIMIT 1`;
  if(!supplier.length)return send(res,400,{error:"supplier_not_found"});
  if(!Array.isArray(input.items)||input.items.length<1||input.items.length>50)return send(res,400,{error:"add_at_least_one_product"});
  const items=[];let total=0;
  for(const raw of input.items){
   const productId=clean(raw.product_id),quantity=amount(raw.quantity),unitPrice=amount(raw.unit_price);
   if(!/^[0-9a-f-]{36}$/i.test(productId)||!Number.isFinite(quantity)||quantity<=0||!Number.isFinite(unitPrice)||unitPrice<=0)return send(res,400,{error:"invalid_purchase_item"});
   const products=await sql`SELECT id,name,unit FROM products WHERE id=${productId} AND workspace_id=${workspaceId} AND active=true LIMIT 1`;
   if(!products.length)return send(res,400,{error:"product_not_found"});
   const product=products[0],lineTotal=Math.round(quantity*unitPrice*100)/100;
   total=Math.round((total+lineTotal)*100)/100;
   items.push({productId,productName:product.name,unit:product.unit,quantity,unitPrice,lineTotal,afnUnitCost:Math.round(unitPrice*rate*10000)/10000});
  }
  if(paid>total)return send(res,400,{error:"paid_exceeds_total"});
  const purchaseId=crypto.randomUUID(),documentNo="BUY-"+Date.now().toString(36).toUpperCase()+"-"+crypto.randomBytes(2).toString("hex").toUpperCase();
  const notes=clean(input.notes);if(notes.length>1000)return send(res,400,{error:"notes_too_long"});
  const statements=[
   sql`INSERT INTO purchases(id,workspace_id,supplier_id,document_no,currency,exchange_rate,total_amount,paid_amount,notes)
    VALUES(${purchaseId},${workspaceId},${supplierId},${documentNo},${currency},${rate},${total},${paid},${notes||null})`
  ];
  for(const item of items){
   statements.push(sql`INSERT INTO purchase_items(purchase_id,product_id,quantity,unit,unit_cost,currency,line_total)
    VALUES(${purchaseId},${item.productId},${item.quantity},${item.unit},${item.unitPrice},${currency},${item.lineTotal})`);
   statements.push(sql`INSERT INTO stock_movements(workspace_id,product_id,movement_type,quantity_delta,unit,unit_cost,source_id,notes)
    VALUES(${workspaceId},${item.productId},'purchase',${item.quantity},${item.unit},${item.afnUnitCost},${purchaseId},${"خرید "+documentNo})`);
   statements.push(sql`INSERT INTO stock_cost_layers(workspace_id,product_id,source_purchase_id,quantity_received,quantity_remaining,unit_cost)
    VALUES(${workspaceId},${item.productId},${purchaseId},${item.quantity},${item.quantity},${item.afnUnitCost})`);
  }
  if(paid>0)statements.push(sql`INSERT INTO payments(workspace_id,supplier_id,purchase_id,amount,currency,exchange_rate,notes)
    VALUES(${workspaceId},${supplierId},${purchaseId},${paid},${currency},${rate},${"پرداخت خرید "+documentNo})`);
  await sql.transaction(statements);
  return send(res,201,{ok:true,purchase:{id:purchaseId,document_no:documentNo,total_amount:total,paid_amount:paid,currency,item_count:items.length}});
 }catch(error){console.error("Asia purchases API error:",error?.message||"unknown");return send(res,500,{error:"server_error"})}
};