export interface Env {
  DB: D1Database;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  REDIRECT_URI: string;
  TOKEN_KEY: string; // base64, 32 bytes, encrypts refresh tokens in D1
  ADMIN_TOKEN: string; // bearer token protecting the API
  WEB_ORIGIN: string; // GitHub Pages origin, for CORS
}

const SCOPES = [
  "https://www.googleapis.com/auth/drive",
  "https://www.googleapis.com/auth/userinfo.email",
].join(" ");

// ---------- token encryption (AES-GCM) ----------

async function aesKey(env: Env) {
  const raw = Uint8Array.from(atob(env.TOKEN_KEY), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function encrypt(env: Env, text: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const buf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await aesKey(env),
    new TextEncoder().encode(text),
  );
  const out = new Uint8Array(iv.length + buf.byteLength);
  out.set(iv);
  out.set(new Uint8Array(buf), iv.length);
  return btoa(String.fromCharCode(...out));
}

async function decrypt(env: Env, enc: string) {
  const data = Uint8Array.from(atob(enc), (c) => c.charCodeAt(0));
  const buf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: data.slice(0, 12) },
    await aesKey(env),
    data.slice(12),
  );
  return new TextDecoder().decode(buf);
}

// ---------- Google helpers ----------

async function accessToken(env: Env, accountId: number): Promise<string> {
  const row = await env.DB.prepare("SELECT refresh_token_enc FROM accounts WHERE id = ?")
    .bind(accountId)
    .first<{ refresh_token_enc: string }>();
  if (!row) throw new Error(`account ${accountId} not found`);
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: await decrypt(env, row.refresh_token_enc),
      grant_type: "refresh_token",
    }),
  });
  if (!res.ok) throw new Error(`token refresh failed: ${res.status}`);
  return ((await res.json()) as { access_token: string }).access_token;
}

async function syncQuota(env: Env, accountId: number) {
  const token = await accessToken(env, accountId);
  const res = await fetch("https://www.googleapis.com/drive/v3/about?fields=storageQuota", {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`about.get failed: ${res.status}`);
  const { storageQuota } = (await res.json()) as {
    storageQuota: { limit?: string; usage: string };
  };
  await env.DB.prepare(
    "UPDATE accounts SET quota_total = ?, quota_used = ?, synced_at = CURRENT_TIMESTAMP WHERE id = ?",
  )
    .bind(Number(storageQuota.limit ?? 0), Number(storageQuota.usage), accountId)
    .run();
}

/** Account with the most free space that can fit `size` bytes. */
async function pickAccount(env: Env, size: number) {
  return env.DB.prepare(
    `SELECT id, email, quota_total - quota_used AS free
       FROM accounts
      WHERE quota_total - quota_used >= ?
      ORDER BY free DESC LIMIT 1`,
  )
    .bind(size)
    .first<{ id: number; email: string; free: number }>();
}


const DRIVE = "https://www.googleapis.com/drive/v3";

async function driveFetch(env: Env, accountId: number, url: string, init: RequestInit = {}) {
  const token = await accessToken(env, accountId);
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${token}`);
  return fetch(url, { ...init, headers });
}

/** Folder in each account where all unified-drive files live (created on first use). */
async function rootFolder(env: Env, accountId: number): Promise<string> {
  const row = await env.DB.prepare("SELECT root_folder_id FROM accounts WHERE id = ?")
    .bind(accountId)
    .first<{ root_folder_id: string | null }>();
  if (row?.root_folder_id) return row.root_folder_id;
  const res = await driveFetch(env, accountId, `${DRIVE}/files?fields=id`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "UnifiedDrive", mimeType: "application/vnd.google-apps.folder" }),
  });
  if (!res.ok) throw new Error(`create root folder failed: ${res.status}`);
  const { id } = (await res.json()) as { id: string };
  await env.DB.prepare("UPDATE accounts SET root_folder_id = ? WHERE id = ?").bind(id, accountId).run();
  return id;
}

function normPath(p: string) {
  const clean = "/" + p.split("/").filter((x) => x && x !== "." && x !== "..").join("/");
  if (clean === "/") throw new Error("empty path");
  return clean;
}

// ---------- HTTP ----------

function cors(env: Env, res: Response) {
  const h = new Headers(res.headers);
  h.set("Access-Control-Allow-Origin", env.WEB_ORIGIN);
  h.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
  h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  return new Response(res.body, { status: res.status, headers: h });
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function route(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);

  if (req.method === "OPTIONS") return new Response(null, { status: 204 });

  // OAuth callback is hit by Google's redirect, protected by `state`.
  if (url.pathname === "/oauth/callback") {
    const code = url.searchParams.get("code");
    if (!code) return json({ error: "missing code" }, 400);
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      body: new URLSearchParams({
        code,
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: env.REDIRECT_URI,
        grant_type: "authorization_code",
      }),
    });
    const tokens = (await tokenRes.json()) as {
      access_token?: string;
      refresh_token?: string;
    };
    if (!tokens.access_token || !tokens.refresh_token) {
      return json({ error: "no refresh token; revoke app access and retry" }, 400);
    }
    const info = (await (
      await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      })
    ).json()) as { email: string };
    const enc = await encrypt(env, tokens.refresh_token);
    await env.DB.prepare(
      `INSERT INTO accounts (email, refresh_token_enc) VALUES (?, ?)
       ON CONFLICT(email) DO UPDATE SET refresh_token_enc = excluded.refresh_token_enc`,
    )
      .bind(info.email, enc)
      .run();
    const acc = await env.DB.prepare("SELECT id FROM accounts WHERE email = ?")
      .bind(info.email)
      .first<{ id: number }>();
    await syncQuota(env, acc!.id);
    return Response.redirect(env.WEB_ORIGIN, 302);
  }

  // Everything else needs the admin bearer token.
  if (req.headers.get("Authorization") !== `Bearer ${env.ADMIN_TOKEN}`) {
    return json({ error: "unauthorized" }, 401);
  }

  if (url.pathname === "/oauth/start") {
    const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    auth.search = new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      redirect_uri: env.REDIRECT_URI,
      response_type: "code",
      scope: SCOPES,
      access_type: "offline",
      prompt: "consent select_account",
    }).toString();
    return json({ url: auth.toString() });
  }

  if (url.pathname === "/accounts") {
    const { results } = await env.DB.prepare(
      "SELECT id, email, quota_total, quota_used, synced_at FROM accounts ORDER BY id",
    ).all();
    return json(results);
  }

  if (url.pathname === "/pool") {
    const row = await env.DB.prepare(
      "SELECT COALESCE(SUM(quota_total),0) AS total, COALESCE(SUM(quota_used),0) AS used FROM accounts",
    ).first<{ total: number; used: number }>();
    return json({ total: row!.total, used: row!.used, free: row!.total - row!.used });
  }

  if (url.pathname === "/upload-target") {
    const size = Number(url.searchParams.get("size") ?? 0);
    const acc = await pickAccount(env, size);
    if (!acc) return json({ error: "no account has enough free space" }, 507);
    return json(acc);
  }

  // Step 1 of upload: pick an account, open a resumable session the browser can PUT to directly.
  if (url.pathname === "/files/init-upload" && req.method === "POST") {
    const { path, size, mime } = (await req.json()) as { path: string; size: number; mime?: string };
    const vpath = normPath(path);
    if (await env.DB.prepare("SELECT 1 FROM files WHERE virtual_path = ?").bind(vpath).first()) {
      return json({ error: "path already exists" }, 409);
    }
    const acc = await pickAccount(env, size);
    if (!acc) return json({ error: "no account has enough free space" }, 507);
    const parent = await rootFolder(env, acc.id);
    const res = await driveFetch(
      env,
      acc.id,
      "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&fields=id",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=UTF-8",
          "X-Upload-Content-Length": String(size),
          // Drive ties CORS for the session URL to this origin.
          Origin: env.WEB_ORIGIN,
          ...(mime ? { "X-Upload-Content-Type": mime } : {}),
        },
        body: JSON.stringify({ name: vpath.split("/").pop(), parents: [parent] }),
      },
    );
    const sessionUrl = res.headers.get("Location");
    if (!res.ok || !sessionUrl) return json({ error: `drive init failed: ${res.status}` }, 502);
    return json({ account_id: acc.id, session_url: sessionUrl, path: vpath });
  }

  // Step 2: after the browser finished the PUT, register the file in the index.
  if (url.pathname === "/files/commit" && req.method === "POST") {
    const { account_id, drive_file_id, path } = (await req.json()) as {
      account_id: number; drive_file_id: string; path: string;
    };
    const res = await driveFetch(env, account_id, `${DRIVE}/files/${drive_file_id}?fields=id,size,mimeType,md5Checksum`);
    if (!res.ok) return json({ error: `file not found in drive: ${res.status}` }, 404);
    const f = (await res.json()) as { id: string; size?: string; mimeType: string; md5Checksum?: string };
    await env.DB.prepare(
      "INSERT INTO files (account_id, drive_file_id, virtual_path, size, mime, md5) VALUES (?,?,?,?,?,?)",
    )
      .bind(account_id, f.id, normPath(path), Number(f.size ?? 0), f.mimeType, f.md5Checksum ?? null)
      .run();
    await syncQuota(env, account_id);
    return json({ ok: true });
  }

  if (url.pathname === "/files" && req.method === "GET") {
    const prefix = normPath(url.searchParams.get("prefix") || "/x").replace(/\/x$/, "") ;
    const like = (prefix === "" ? "/" : prefix + "/") + "%";
    const { results } = await env.DB.prepare(
      `SELECT f.id, f.virtual_path, f.size, f.mime, a.email AS account
         FROM files f JOIN accounts a ON a.id = f.account_id
        WHERE f.virtual_path LIKE ? ORDER BY f.virtual_path`,
    ).bind(like).all();
    return json(results);
  }

  if (url.pathname === "/files/download" && req.method === "GET") {
    const f = await env.DB.prepare("SELECT account_id, drive_file_id, virtual_path, mime FROM files WHERE id = ?")
      .bind(Number(url.searchParams.get("id")))
      .first<{ account_id: number; drive_file_id: string; virtual_path: string; mime: string }>();
    if (!f) return json({ error: "not found" }, 404);
    const res = await driveFetch(env, f.account_id, `${DRIVE}/files/${f.drive_file_id}?alt=media`);
    if (!res.ok) return json({ error: `drive download failed: ${res.status}` }, 502);
    const name = encodeURIComponent(f.virtual_path.split("/").pop()!);
    return new Response(res.body, {
      headers: {
        "Content-Type": f.mime || "application/octet-stream",
        "Content-Disposition": `attachment; filename*=UTF-8''${name}`,
      },
    });
  }

  // Delete = move to the owner's Drive trash (recoverable), then drop from the index.
  if (url.pathname === "/files/delete" && req.method === "POST") {
    const { id } = (await req.json()) as { id: number };
    const f = await env.DB.prepare("SELECT account_id, drive_file_id FROM files WHERE id = ?")
      .bind(id)
      .first<{ account_id: number; drive_file_id: string }>();
    if (!f) return json({ error: "not found" }, 404);
    const res = await driveFetch(env, f.account_id, `${DRIVE}/files/${f.drive_file_id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ trashed: true }),
    });
    if (!res.ok) return json({ error: `trash failed: ${res.status}` }, 502);
    await env.DB.prepare("DELETE FROM files WHERE id = ?").bind(id).run();
    return json({ ok: true });
  }

  return json({ error: "not found" }, 404);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    try {
      return cors(env, await route(req, env));
    } catch (e) {
      return cors(env, json({ error: String(e) }, 500));
    }
  },

  // Cron: refresh quotas for every account. Rebalance (phase 4) hooks in here.
  async scheduled(_ev: ScheduledController, env: Env) {
    const { results } = await env.DB.prepare("SELECT id FROM accounts").all<{ id: number }>();
    for (const { id } of results) {
      try {
        await syncQuota(env, id);
      } catch (e) {
        console.error(`quota sync failed for account ${id}`, e);
      }
    }
  },
};
