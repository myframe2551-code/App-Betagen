const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    if (request.method === "POST" && url.pathname === "/register") {
      try {
        const data = await request.json();

        const nickname = String(data.nickname || "").trim();
        const username = String(data.username || "").trim();
        const age = parseInt(data.age, 10);
        const gender = String(data.gender || "").trim();
        const phone = String(data.phone || "").trim();
        const password = String(data.password || "");

        if (!nickname || !username || !Number.isInteger(age) || age < 1 || !gender || !phone || !password) {
          return json({
            success: false,
            message: "กรุณากรอกข้อมูลให้ครบ"
          }, 400);
        }

        const existing = await env.DB
          .prepare("SELECT id FROM users WHERE username = ? OR phone = ? LIMIT 1")
          .bind(username, phone)
          .first();

        if (existing) {
          return json({
            success: false,
            message: "ชื่อผู้ใช้หรือเบอร์โทรศัพท์ถูกใช้แล้ว"
          }, 409);
        }

        const passwordHash = await hashPassword(password);

        await env.DB
          .prepare(
            `INSERT INTO users
            (nickname, username, age, gender, phone, password_hash)
            VALUES (?, ?, ?, ?, ?, ?)`
          )
          .bind(
            nickname,
            username,
            age,
            gender,
            phone,
            passwordHash
          )
          .run();

        return json({
          success: true,
          message: "สมัครสมาชิกสำเร็จ"
        }, 200);

      } catch (error) {
        return json({
          success: false,
          message: "เกิดข้อผิดพลาดของเซิร์ฟเวอร์"
        }, 500);
      }
    }

    if (request.method === "GET" && url.pathname === "/users") {
      try {
        const result = await env.DB
          .prepare(
            `SELECT id, nickname, username, age, gender, created_at
             FROM users
             ORDER BY id DESC`
          )
          .all();

        return json({
          success: true,
          users: result.results
        }, 200);

      } catch (error) {
        return json({
          success: false,
          message: "ไม่สามารถโหลดสมาชิกได้"
        }, 500);
      }
    }

    return json({
      success: false,
      message: "API not found"
    }, 404);
  }
};

async function hashPassword(password) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    {
      name: "PBKDF2"
    },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return toBase64(salt) + ":" + toBase64(new Uint8Array(bits));
}

function toBase64(bytes) {
  let binary = "";

  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary);
}

function json(data, status) {
  return new Response(
    JSON.stringify(data),
    {
      status: status,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json; charset=UTF-8"
      }
    }
  );
}
