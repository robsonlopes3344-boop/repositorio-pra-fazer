const crypto=require('crypto');
function key(){let raw=process.env.INVENTORY_ENCRYPTION_KEY||'';if(!/^[0-9a-f]{64}$/i.test(raw))throw Error('Estoque digital indisponível.');return Buffer.from(raw,'hex')}
function encode(value){let k=key(),iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',k,iv),bytes=Buffer.concat([c.update(value,'utf8'),c.final()]);return Buffer.concat([iv,c.getAuthTag(),bytes]).toString('base64')}
function decode(value){let buf=Buffer.from(value,'base64'),d=crypto.createDecipheriv('aes-256-gcm',key(),buf.subarray(0,12));d.setAuthTag(buf.subarray(12,28));return Buffer.concat([d.update(buf.subarray(28)),d.final()]).toString('utf8')}
function fingerprint(value){return crypto.createHmac('sha256',key()).update(value).digest('hex')}
module.exports={encode,decode,fingerprint,key};
