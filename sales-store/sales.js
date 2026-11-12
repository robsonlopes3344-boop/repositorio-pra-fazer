const crypto = require('crypto');
const {ChannelType, PermissionFlagsBits, ActionRowBuilder, ButtonBuilder, ButtonStyle, EmbedBuilder} = require('discord.js');
const endpoint = 'https://api.checkout.infinitepay.io';
module.exports = function setupSales({app, pool, discord, refreshProductCards}) {
  const configured = () => process.env.INFINITEPAY_API_KEY && process.env.INFINITEPAY_HANDLE && /^https:\/\//.test(process.env.PUBLIC_URL || '');
  async function call(path, data) {
    const resp = await fetch(endpoint + path, {method:'POST',headers:{'Content-Type':'application/json','X-Api-Key':process.env.INFINITEPAY_API_KEY},body:JSON.stringify(data),signal:AbortSignal.timeout(12000)});
    if(!resp.ok) throw Error('InfinitePay indisponível: HTTP '+resp.status);
    return resp.json();
  }
  async function reserve(productId, buyer, guild) {
    const c=await pool.connect();
    try {
      await c.query('BEGIN');
      const p=(await c.query('SELECT * FROM store_private.store_products WHERE id=$1 FOR UPDATE',[productId])).rows[0];
      if(!p || !p.active || p.stock<1) throw Error('Produto sem estoque.');
      const previous=(await c.query("SELECT id FROM store_private.store_orders WHERE product_id=$1 AND buyer_id=$2 AND status IN ('creating','pending')",[productId,buyer])).rows[0];
      if(previous) throw Error('Você já tem um pedido aberto deste produto.');
      const id=crypto.randomUUID();
      await c.query('UPDATE store_private.store_products SET stock=stock-1 WHERE id=$1',[p.id]);
      await c.query("INSERT INTO store_private.store_orders(id,product_id,product_name,price,buyer_id,guild_id,status) VALUES($1,$2,$3,$4,$5,$6,'creating')",[id,p.id,p.name,p.price,buyer,guild]);
      await c.query('COMMIT'); return {id,product:p};
    } catch(e){await c.query('ROLLBACK');throw e} finally {c.release()}
  }
  async function release(id){const c=await pool.connect();try{await c.query('BEGIN');const o=(await c.query("UPDATE store_private.store_orders SET status='failed' WHERE id=$1 AND status='creating' RETURNING product_id",[id])).rows[0];if(o)await c.query('UPDATE store_private.store_products SET stock=stock+1 WHERE id=$1',[o.product_id]);await c.query('COMMIT')}catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}}
  async function buy(i, productId){
    if(!configured())return i.reply({content:'As compras ainda não foram configuradas. Procure a equipe.',ephemeral:true});
    await i.deferReply({ephemeral:true}); let order; let checkoutAttempted=false;
    try{
      order=await reserve(productId,i.user.id,i.guildId);
      if(refreshProductCards){const latest=(await pool.query('SELECT * FROM store_private.store_products WHERE id=$1',[order.product.id])).rows[0];if(latest)await refreshProductCards(latest).catch(e=>console.error('Atualização do cartão:',e.message))}
      const webhook = new URL('/webhook/infinitepay',process.env.PUBLIC_URL).href;
      checkoutAttempted=true;
      const created=await call('/links',{handle:process.env.INFINITEPAY_HANDLE,order_nsu:order.id,items:[{quantity:1,price:order.product.price,description:order.product.name}],webhook_url:webhook,options:{single_payment:true,require_delivery_address:false,valid_until:new Date(Date.now()+60*60*1000).toISOString()}});
      const url=created.url || created.checkout_url;
      const parsed=new URL(url);if(parsed.protocol!=='https:'||!(parsed.hostname==='infinitepay.io'||parsed.hostname.endsWith('.infinitepay.io')))throw Error('Link de pagamento inválido.');
      await pool.query("UPDATE store_private.store_orders SET status='pending',checkout_url=$2 WHERE id=$1 AND status='creating'",[order.id,url]);
      const ch=await i.guild.channels.create({name:`compra-${i.user.username}`.toLowerCase().replace(/[^a-z0-9-]/g,'').slice(0,70),type:ChannelType.GuildText,permissionOverwrites:[{id:i.guild.id,deny:[PermissionFlagsBits.ViewChannel]},{id:i.user.id,allow:[PermissionFlagsBits.ViewChannel,PermissionFlagsBits.SendMessages,PermissionFlagsBits.ReadMessageHistory]},{id:discord.user.id,allow:[PermissionFlagsBits.ViewChannel,PermissionFlagsBits.SendMessages,PermissionFlagsBits.ReadMessageHistory]}]});
      await pool.query('UPDATE store_private.store_orders SET ticket_channel_id=$2 WHERE id=$1',[order.id,ch.id]);
      const button=new ButtonBuilder().setLabel('Pagar com InfinitePay').setStyle(ButtonStyle.Link).setURL(url);
      const embed = new EmbedBuilder().setColor(0x9c5cff).setTitle(order.product.name.slice(0,256)).setDescription(order.product.description.slice(0,4000)).addFields({name:'Valor',value:`R$ ${(order.product.price/100).toFixed(2)}`,inline:true},{name:'Pedido',value:order.id,inline:true}).setFooter({text:'Após a confirmação, a equipe providenciará a entrega.'}); if(order.product.image)embed.setImage(order.product.image);
      await ch.send({content:`<@${i.user.id}> seu pedido está pronto para pagamento.`,embeds:[embed],allowedMentions:{parse:[],users:[i.user.id]},components:[new ActionRowBuilder().addComponents(button)]});
      await i.editReply({content:`Seu pedido foi criado: ${ch}.`});
    }catch(e){console.error('Pedido:',e.message);if(order && !checkoutAttempted) await release(order.id).catch(()=>{});await i.editReply({content:order?'Não foi possível concluir o ticket. Consulte a equipe antes de tentar novamente.':'Não foi possível abrir o pedido: '+e.message})}
  }
  discord.on('interactionCreate',i=>{if(i.guildId!==process.env.DISCORD_GUILD_ID)return; if(i.isStringSelectMenu()&&i.customId==='store:select')buy(i,i.values[0]).catch(e=>console.error('Compra:',e.message));else if(i.isButton()&&/^store:buy:\d+$/.test(i.customId))buy(i,i.customId.slice(10)).catch(e=>console.error('Compra:',e.message))});
  app.post('/webhook/infinitepay',async(req,res)=>{
    try{
      const {order_nsu,transaction_nsu,invoice_slug,slug}=req.body||{};const invoice=invoice_slug||slug;
      if(typeof order_nsu!=='string'||typeof transaction_nsu!=='string'||typeof invoice!=='string')return res.status(400).json({error:'Dados inválidos'});
      const o=(await pool.query('SELECT * FROM store_private.store_orders WHERE id=$1',[order_nsu])).rows[0];if(!o)return res.status(400).json({error:'Pedido desconhecido'});
      if(o.status==='paid')return res.sendStatus(200);
      const verified=await call('/payment_check',{handle:process.env.INFINITEPAY_HANDLE,order_nsu,transaction_nsu,slug:invoice});
      if(verified.success!==true||verified.paid!==true||Number(verified.amount)!==o.price)return res.status(400).json({error:'Pagamento não confirmado'});
      await pool.query("UPDATE store_private.store_orders SET status='paid',transaction_nsu=$2,paid_at=NOW(),log_pending=true WHERE id=$1 AND status IN ('creating','pending')",[order_nsu,transaction_nsu]);
      res.sendStatus(200); flushLogs().catch(e=>console.error('Logs:',e.message));
    }catch(e){console.error('Webhook:',e.message);res.status(500).json({error:'Falha na confirmação'})}
  });
  let flushing=false;
  async function flushLogs(){if(flushing||!process.env.SALE_LOG_WEBHOOK)return;flushing=true;try{for(const o of (await pool.query("SELECT * FROM store_private.store_orders WHERE status='paid' AND log_pending=true ORDER BY paid_at LIMIT 20")).rows){const response=await fetch(process.env.SALE_LOG_WEBHOOK,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:`<@${o.buyer_id}> comprou **${o.product_name.replace(/[*_`~]/g,'')}** · R$ ${(o.price/100).toFixed(2)}`,allowed_mentions:{parse:[],users:[o.buyer_id]}}),signal:AbortSignal.timeout(10000)});if(!response.ok)throw Error('Discord webhook HTTP '+response.status);await pool.query('UPDATE store_private.store_orders SET log_pending=false WHERE id=$1',[o.id]);if(o.ticket_channel_id){const c=await discord.channels.fetch(o.ticket_channel_id).catch(()=>null);if(c)await c.send('✅ Pagamento confirmado. A equipe fará a entrega.').catch(()=>{})}}}finally{flushing=false}}
  return {init:async()=>{await pool.query(`CREATE TABLE IF NOT EXISTS store_private.store_orders(id UUID PRIMARY KEY,product_id BIGINT NOT NULL REFERENCES store_private.store_products(id),product_name TEXT NOT NULL,price INTEGER NOT NULL,buyer_id TEXT NOT NULL,guild_id TEXT NOT NULL,status TEXT NOT NULL,checkout_url TEXT,ticket_channel_id TEXT,transaction_nsu TEXT,paid_at TIMESTAMPTZ,log_pending BOOLEAN NOT NULL DEFAULT false,created_at TIMESTAMPTZ NOT NULL DEFAULT now()); CREATE UNIQUE INDEX IF NOT EXISTS store_orders_one_open ON store_private.store_orders(buyer_id,product_id) WHERE status IN ('creating','pending'); CREATE UNIQUE INDEX IF NOT EXISTS store_orders_unique_transaction ON store_private.store_orders(transaction_nsu) WHERE transaction_nsu IS NOT NULL`);setInterval(()=>flushLogs().catch(e=>console.error('Logs:',e.message)),60000).unref()}};
};
