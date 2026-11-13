import postgres from "npm:postgres@3.4.7";

const dbUrl = Deno.env.get("SUPABASE_DB_URL");
if (!dbUrl) throw new Error("Banco indisponivel");
const sql = postgres(dbUrl, { prepare: false, max: 1, idle_timeout: 20, connect_timeout: 10 });
const json = (data: unknown, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json", "cache-control": "no-store" },
});
const sha = async (value: string) => Array.from(
  new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))),
  byte => byte.toString(16).padStart(2, "0"),
).join("");
const validId = (value: unknown): value is string => typeof value === "string" && /^\d{1,15}$/.test(value);
const validHash = (value: unknown): value is string => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
const validCiphertext = (value: unknown): value is string => typeof value === "string" && /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value) && value.length <= 512;

Deno.serve(async (req: Request) => {
  try {
    if (req.method !== "POST") return json({ error: "method" }, 405);
    const supplied = req.headers.get("x-collins-backend") || "";
    if (supplied.length < 32 || supplied.length > 256) return json({ error: "unauthorized" }, 401);
    const secretRows = await sql`SELECT secret_hash FROM collins_private.service_secrets WHERE name='edge_backend'`;
    const hash = await sha(supplied);
    const expected = String(secretRows[0]?.secret_hash || "");
    let difference = hash.length ^ expected.length;
    for (let index = 0; index < 64; index++) difference |= (hash.charCodeAt(index) || 0) ^ (expected.charCodeAt(index) || 0);
    if (difference !== 0) return json({ error: "unauthorized" }, 401);

    const text = await req.text();
    if (text.length > 4096) return json({ error: "too large" }, 413);
    const body = JSON.parse(text);
    const op = body.op;

    if (op === "health") {
      await sql`SELECT 1`;
      return json({ ok: true });
    }
    if (op === "verify") {
      if (!validHash(body.keyHash)) return json({ error: "invalid" }, 400);
      const rows = await sql`SELECT 1 FROM collins_private.licenses WHERE key_hash=${body.keyHash} AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())`;
      return json({ valid: rows.length > 0 });
    }
    if (op === "create") {
      if (!validHash(body.keyHash) || !validCiphertext(body.keyCiphertext) || typeof body.label !== "string" || body.label.length > 100 || !Number.isInteger(body.days) || body.days < 1 || body.days > 3650) return json({ error: "invalid" }, 400);
      const rows = await sql`INSERT INTO collins_private.licenses(key_hash,key_ciphertext,label,expires_at) VALUES(${body.keyHash},${body.keyCiphertext},${body.label},now()+(${body.days} * interval '1 day')) RETURNING id,label,expires_at`;
      return json(rows[0]);
    }
    if (op === "rotateKey") {
      if (!validId(body.id) || !validHash(body.keyHash) || !validCiphertext(body.keyCiphertext)) return json({ error: "invalid" }, 400);
      const rows = await sql`UPDATE collins_private.licenses SET key_hash=${body.keyHash},key_ciphertext=${body.keyCiphertext} WHERE id=${body.id} RETURNING id`;
      return json({ changed: rows.length > 0 });
    }
    if (op === "register") {
      if (typeof body.username !== "string" || !/^[a-z0-9_]{4,24}$/.test(body.username) || !validHash(body.keyHash) || !validHash(body.deviceHash) || typeof body.passwordHash !== "string" || body.passwordHash.length > 256) return json({ error: "invalid" }, 400);
      try {
        const rows = await sql`INSERT INTO collins_private.accounts(username,password_hash,device_hash,license_id) SELECT ${body.username},${body.passwordHash},${body.deviceHash},id FROM collins_private.licenses WHERE key_hash=${body.keyHash} AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now()) RETURNING id`;
        return json({ created: rows.length > 0 });
      } catch {
        return json({ created: false });
      }
    }
    if (op === "account") {
      if (typeof body.username !== "string" || !/^[a-z0-9_]{4,24}$/.test(body.username)) return json({ error: "invalid" }, 400);
      const rows = await sql`SELECT a.id,a.license_id,a.username,a.password_hash,a.device_hash FROM collins_private.accounts a JOIN collins_private.licenses l ON l.id=a.license_id WHERE a.username=${body.username} AND l.revoked_at IS NULL AND (l.expires_at IS NULL OR l.expires_at>now())`;
      return json({ account: rows[0] || null });
    }
    if (op === "bindDevice") {
      if (typeof body.username !== "string" || !/^[a-z0-9_]{4,24}$/.test(body.username) || !validHash(body.deviceHash)) return json({ error: "invalid" }, 400);
      const rows = await sql`UPDATE collins_private.accounts SET device_hash=${body.deviceHash},last_login=now() WHERE username=${body.username} AND (device_hash IS NULL OR device_hash=${body.deviceHash}) RETURNING id`;
      return json({ bound: rows.length > 0 });
    }
    if (op === "session") {
      if (typeof body.username !== "string" || !/^[a-z0-9_]{4,24}$/.test(body.username) || !validHash(body.deviceHash)) return json({ error: "invalid" }, 400);
      const rows = await sql`SELECT 1 FROM collins_private.accounts a JOIN collins_private.licenses l ON l.id=a.license_id WHERE a.username=${body.username} AND a.device_hash=${body.deviceHash} AND l.revoked_at IS NULL AND (l.expires_at IS NULL OR l.expires_at>now())`;
      return json({ valid: rows.length > 0 });
    }
    if (op === "requestDeviceReset") {
      if (typeof body.username !== "string" || !/^[a-z0-9_]{4,24}$/.test(body.username) || !validHash(body.newDeviceHash)) return json({ error: "invalid" }, 400);
      const rows = await sql`
        INSERT INTO collins_private.device_reset_requests(license_id,account_id,old_device_hash,new_device_hash)
        SELECT license_id,id,device_hash,${body.newDeviceHash}
        FROM collins_private.accounts
        WHERE username=${body.username} AND device_hash IS NOT NULL AND device_hash<>${body.newDeviceHash}
        ON CONFLICT (account_id) WHERE status='pending'
        DO UPDATE SET old_device_hash=excluded.old_device_hash,new_device_hash=excluded.new_device_hash,created_at=now(),resolved_at=NULL
        RETURNING id,status`;
      return rows.length ? json(rows[0]) : json({ error: "reset_not_needed" }, 409);
    }
    if (op === "listResetRequests") {
      const rows = await sql`
        SELECT r.id,r.license_id,r.old_device_hash,r.new_device_hash,r.status,r.created_at,r.resolved_at,a.username,l.label
        FROM collins_private.device_reset_requests r
        JOIN collins_private.accounts a ON a.id=r.account_id
        JOIN collins_private.licenses l ON l.id=r.license_id
        ORDER BY (r.status='pending') DESC,r.created_at DESC
        LIMIT 500`;
      return json(rows);
    }
    if (op === "resolveResetRequest") {
      if (!validId(body.id) || !["approve", "reject"].includes(body.decision)) return json({ error: "invalid" }, 400);
      const result = await sql.begin(async transaction => {
        const requests = await transaction`SELECT id,account_id,new_device_hash FROM collins_private.device_reset_requests WHERE id=${body.id} AND status='pending' FOR UPDATE`;
        const request = requests[0];
        if (!request) return { changed: false };
        if (body.decision === "approve") {
          await transaction`UPDATE collins_private.accounts SET device_hash=${request.new_device_hash},last_login=NULL WHERE id=${request.account_id}`;
        }
        const status = body.decision === "approve" ? "approved" : "rejected";
        await transaction`UPDATE collins_private.device_reset_requests SET status=${status},resolved_at=now() WHERE id=${body.id}`;
        return { changed: true, status };
      });
      return json(result);
    }
    if (op === "resetDevice") {
      if (!validId(body.id)) return json({ error: "invalid" }, 400);
      const result = await sql.begin(async transaction => {
        const rows = await transaction`UPDATE collins_private.accounts SET device_hash=NULL WHERE license_id=${body.id} RETURNING id`;
        if (rows.length) await transaction`UPDATE collins_private.device_reset_requests SET status='rejected',resolved_at=now() WHERE license_id=${body.id} AND status='pending'`;
        return { changed: rows.length > 0 };
      });
      return json(result);
    }
    if (op === "specs") {
      if (typeof body.username !== "string" || !/^[a-z0-9_]{4,24}$/.test(body.username) || !validHash(body.deviceHash) || typeof body.shared !== "boolean") return json({ error: "invalid" }, 400);
      let specs: Record<string, string> | null = null;
      if (body.shared) {
        if (!body.specs || typeof body.specs !== "object" || Array.isArray(body.specs)) return json({ error: "invalid" }, 400);
        specs = {};
        for (const name of ["os", "cpu", "gpu", "ram", "motherboard", "storage", "display", "system"]) {
          const value = body.specs[name];
          if (value !== undefined) {
            if (typeof value !== "string" || value.length > 200) return json({ error: "invalid" }, 400);
            specs[name] = value;
          }
        }
      }
      const encoded = specs === null ? null : sql.json(specs);
      const rows = await sql`UPDATE collins_private.accounts SET device_specs=${encoded} WHERE username=${body.username} AND device_hash=${body.deviceHash} RETURNING id`;
      return json({ changed: rows.length > 0 });
    }
    if (op === "list") {
      const rows = await sql`SELECT l.id,l.key_ciphertext,l.label,l.created_at,l.expires_at,l.revoked_at,a.username,a.device_specs,a.last_login FROM collins_private.licenses l LEFT JOIN collins_private.accounts a ON a.license_id=l.id ORDER BY l.id DESC LIMIT 500`;
      return json(rows);
    }
    if (op === "extend") {
      if (!validId(body.id) || !Number.isInteger(body.days) || body.days < 1 || body.days > 3650) return json({ error: "invalid" }, 400);
      const rows = await sql`UPDATE collins_private.licenses SET expires_at=GREATEST(COALESCE(expires_at,now()),now())+(${body.days} * interval '1 day') WHERE id=${body.id} RETURNING id,expires_at`;
      return json({ changed: rows.length > 0, expires_at: rows[0]?.expires_at });
    }
    if (op === "rename") {
      if (!validId(body.id) || typeof body.label !== "string" || body.label.length > 100) return json({ error: "invalid" }, 400);
      const rows = await sql`UPDATE collins_private.licenses SET label=${body.label} WHERE id=${body.id} RETURNING id`;
      return json({ changed: rows.length > 0 });
    }
    if (op === "revoke" || op === "unban") {
      if (!validId(body.id)) return json({ error: "invalid" }, 400);
      const rows = op === "revoke"
        ? await sql`UPDATE collins_private.licenses SET revoked_at=now() WHERE id=${body.id} AND revoked_at IS NULL RETURNING id`
        : await sql`UPDATE collins_private.licenses SET revoked_at=NULL WHERE id=${body.id} AND revoked_at IS NOT NULL RETURNING id`;
      return json({ changed: rows.length > 0 });
    }
    return json({ error: "invalid" }, 400);
  } catch (error) {
    console.error("collins backend failed", error instanceof Error ? error.name : "error");
    return json({ error: "backend indisponivel" }, 503);
  }
});

