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
  if(new URL(req.url,"https://local.invalid").searchParams.get("action")==="purchase"){
   if(req.method==="GET"){
    const rows=await sql`SELECT p.id,p.document_no,p.purchased_at,p.currency,p.exchange_rate,p.total_amount,p.paid_amount,s.name supplier_name,COALESCE(json_agg(json_build_object('product_id',pi.product_id,'product_name',pr.name,'category',pr.category,'brand',pr.brand,'model',pr.model,'size',pr.size,'quantity',pi.quantity,'unit',pi.unit,'unit_cost',pi.unit_cost,'line_total',pi.line_total)) FILTER(WHERE pi.id IS NOT NULL),'[]'::json) items FROM purchases p LEFT JOIN suppliers s ON s.id=p.supplier_id LEFT JOIN purchase_items pi ON pi.purchase_id=p.id LEFT JOIN products pr ON pr.id=pi.product_id WHERE p.workspace_id=${workspaceId} GROUP BY p.id,s.name ORDER BY p.purchased_at DESC LIMIT 100`;
    return send(res,200,{ok:true,purchases:rows});
   }
   let input;try{input=await readBody(req)}catch{return send(res,413,{error:"request_too_large"})}
   const supplierId=clean(input.supplier_id),currency=clean(input.currency),rate=Number(input.exchange_rate),paid=Number(input.paid_amount||0),notes=clean(input.notes),items=Array.isArray(input.items)?input.items:[];
   if((supplierId&&!/^[0-9a-f-]{36}$/i.test(supplierId))||!["AFN","USD","PKR"].includes(currency)||!Number.isFinite(rate)||rate<=0||!Number.isFinite(paid)||paid<0||items.length<1||items.length>50||notes.length>1000)return send(res,400,{error:"invalid_purchase"});
   if(supplierId){const supplier=await sql`SELECT id FROM suppliers WHERE id=${supplierId} AND workspace_id=${workspaceId} LIMIT 1`;if(!supplier.length)return send(res,400,{error:"supplier_not_found"});}
   const cleanItems=[];
   for(const raw of items){const productId=clean(raw.product_id),quantity=Number(raw.quantity),unitCost=Number(raw.unit_cost);if(!/^[0-9a-f-]{36}$/i.test(productId)||!Number.isFinite(quantity)||quantity<=0||!Number.isFinite(unitCost)||unitCost<0)return send(res,400,{error:"invalid_item"});const product=await sql`SELECT id,unit FROM products WHERE id=${productId} AND workspace_id=${workspaceId} AND active=true LIMIT 1`;if(!product.length)return send(res,400,{error:"product_not_found"});cleanItems.push({product_id:productId,quantity:String(raw.quantity),unit_cost:String(raw.unit_cost),unit:product[0].unit})}
   const jsonItems=JSON.stringify(cleanItems),totals=await sql`SELECT COALESCE(SUM((v->>'quantity')::numeric*(v->>'unit_cost')::numeric),0)::text total FROM jsonb_array_elements(${jsonItems}::jsonb) v`;
   const total=Number(totals[0].total);if(!Number.isFinite(total)||total<=0||paid>total)return send(res,400,{error:"invalid_paid_amount"});if(!supplierId&&Math.abs(paid-total)>0.000001)return send(res,400,{error:"cash_purchase_must_be_fully_paid"});
   const purchaseId=crypto.randomUUID(),documentNo="BUY-"+new Date().toISOString().replace(/[-:TZ.]/g,"").slice(0,14)+"-"+crypto.randomBytes(2).toString("hex").toUpperCase();
   const statements=[sql`INSERT INTO purchases(id,workspace_id,supplier_id,document_no,currency,exchange_rate,total_amount,paid_amount,notes) VALUES(${purchaseId},${workspaceId},${supplierId||null},${documentNo},${currency},${rate},${totals[0].total},${paid},${notes||null})`];
   for(const item of cleanItems){statements.push(sql`INSERT INTO purchase_items(purchase_id,product_id,quantity,unit,unit_cost,currency,line_total) VALUES(${purchaseId},${item.product_id},${item.quantity}::numeric,${item.unit},${item.unit_cost}::numeric,${currency},${item.quantity}::numeric*${item.unit_cost}::numeric)`);statements.push(sql`INSERT INTO stock_movements(workspace_id,product_id,movement_type,quantity_delta,unit,unit_cost,source_id,notes) VALUES(${workspaceId},${item.product_id},'purchase',${item.quantity}::numeric,${item.unit},${item.unit_cost}::numeric*${rate},${purchaseId},${documentNo})`);statements.push(sql`INSERT INTO stock_cost_layers(workspace_id,product_id,source_purchase_id,quantity_received,quantity_remaining,unit_cost) VALUES(${workspaceId},${item.product_id},${purchaseId},${item.quantity}::numeric,${item.quantity}::numeric,${item.unit_cost}::numeric*${rate})`)}
   if(paid>0&&supplierId)statements.push(sql`INSERT INTO payments(workspace_id,supplier_id,purchase_id,amount,currency,exchange_rate,notes) VALUES(${workspaceId},${supplierId},${purchaseId},${paid},${currency},${rate},'پرداخت هنگام ثبت خرید')`);
   await sql.transaction(statements);return send(res,201,{ok:true,purchase:{id:purchaseId,document_no:documentNo,total_amount:totals[0].total,paid_amount:String(paid),currency,exchange_rate:rate,item_count:cleanItems.length}});
  }
  if(req.method==="GET"){const rows=await sql`SELECT s.id,s.name,s.phone,s.address,s.notes,s.created_at,COALESCE((SELECT SUM(b.total_amount*b.exchange_rate) FROM purchases b WHERE b.supplier_id=s.id AND b.workspace_id=s.workspace_id),0) AS total_purchases_afn,COALESCE((SELECT SUM(p.amount*p.exchange_rate) FROM payments p WHERE p.supplier_id=s.id AND p.workspace_id=s.workspace_id),0) AS paid_purchases_afn,COALESCE((SELECT SUM(b.total_amount*b.exchange_rate) FROM purchases b WHERE b.supplier_id=s.id AND b.workspace_id=s.workspace_id),0)-COALESCE((SELECT SUM(p.amount*p.exchange_rate) FROM payments p WHERE p.supplier_id=s.id AND p.workspace_id=s.workspace_id),0) AS balance_afn FROM suppliers s WHERE s.workspace_id=${workspaceId} ORDER BY s.created_at DESC LIMIT 300`;return send(res,200,{ok:true,suppliers:rows})}
  let input;try{input=await readBody(req)}catch{return send(res,413,{error:"request_too_large"})}
  const name=clean(input.name),phone=clean(input.phone),address=clean(input.address),notes=clean(input.notes);
  if(!name||name.length>160)return send(res,400,{error:"invalid_name"});
  if([phone,address,notes].some(v=>v.length>500))return send(res,400,{error:"field_too_long"});
  const rows=await sql`INSERT INTO suppliers(workspace_id,name,phone,address,notes) VALUES(${workspaceId},${name},${phone||null},${address||null},${notes||null}) RETURNING id,name,phone,address,notes,created_at`;
  return send(res,201,{ok:true,supplier:rows[0]});
 }catch(error){console.error("Asia suppliers API error:",error?.message||"unknown");return send(res,500,{error:"server_error"})}
};