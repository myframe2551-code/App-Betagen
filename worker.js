const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
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

        if (
          !nickname ||
          !username ||
          !Number.isInteger(age) ||
          age < 1 ||
          !gender ||
          !phone ||
          !password
        ) {
          return json({
            success: false,
            message: "กรุณากรอกข้อมูลให้ครบ"
          }, 400);
        }

        const existing = await env.DB
          .prepare(
            "SELECT id FROM users WHERE username = ? OR phone = ? LIMIT 1"
          )
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

    if (request.method === "POST" && url.pathname === "/login") {
      try {
        const data = await request.json();

        const username = String(data.username || "").trim();
        const password = String(data.password || "");

        if (!username || !password) {
          return json({
            success: false,
            message: "กรุณากรอกชื่อผู้ใช้และรหัสผ่าน"
          }, 400);
        }

        const user = await env.DB
          .prepare(
            `SELECT id, nickname, username, age, gender, phone, avatar
             FROM users
             WHERE username = ?
             LIMIT 1`
          )
          .bind(username)
          .first();

        if (!user) {
          return json({
            success: false,
            message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"
          }, 401);
        }

        const passwordRow = await env.DB
          .prepare(
            "SELECT password_hash FROM users WHERE id = ? LIMIT 1"
          )
          .bind(user.id)
          .first();

        if (!passwordRow) {
          return json({
            success: false,
            message: "ไม่พบข้อมูลบัญชี"
          }, 401);
        }

        const valid = await verifyPassword(
          password,
          passwordRow.password_hash
        );

        if (!valid) {
          return json({
            success: false,
            message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"
          }, 401);
        }

        return json({
          success: true,
          message: "เข้าสู่ระบบสำเร็จ",
          user: {
            id: user.id,
            nickname: user.nickname,
            username: user.username,
            age: user.age,
            gender: user.gender,
            phone: user.phone,
            avatar: user.avatar || ""
          }
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
            `SELECT id, nickname, username, age, gender, avatar, created_at
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

    if (request.method === "GET" && url.pathname === "/profile") {
      try {
        const username = String(
          url.searchParams.get("username") || ""
        ).trim();

        if (!username) {
          return json({
            success: false,
            message: "ไม่พบชื่อผู้ใช้"
          }, 400);
        }

        const user = await env.DB
          .prepare(
            `SELECT id, nickname, username, age, gender, phone, avatar, created_at
             FROM users
             WHERE username = ?
             LIMIT 1`
          )
          .bind(username)
          .first();

        if (!user) {
          return json({
            success: false,
            message: "ไม่พบข้อมูลผู้ใช้"
          }, 404);
        }

        return json({
          success: true,
          user: user
        }, 200);

      } catch (error) {
        return json({
          success: false,
          message: "ไม่สามารถโหลดโปรไฟล์ได้"
        }, 500);
      }
    }

    if (request.method === "PUT" && url.pathname === "/profile") {
      try {
        const data = await request.json();

        const username = String(data.username || "").trim();
        const nickname = String(data.nickname || "").trim();
        const avatar = String(data.avatar || "");

        if (!username || !nickname) {
          return json({
            success: false,
            message: "กรุณากรอกชื่อเล่น"
          }, 400);
        }

        if (avatar.length > 750000) {
          return json({
            success: false,
            message: "รูปโปรไฟล์มีขนาดใหญ่เกินไป"
          }, 413);
        }

        const user = await env.DB
          .prepare(
            "SELECT id FROM users WHERE username = ? LIMIT 1"
          )
          .bind(username)
          .first();

        if (!user) {
          return json({
            success: false,
            message: "ไม่พบข้อมูลผู้ใช้"
          }, 404);
        }

        await env.DB
          .prepare(
            `UPDATE users
             SET nickname = ?, avatar = ?
             WHERE username = ?`
          )
          .bind(
            nickname,
            avatar,
            username
          )
          .run();

        return json({
          success: true,
          message: "บันทึกโปรไฟล์สำเร็จ"
        }, 200);

      } catch (error) {
        return json({
          success: false,
          message: "ไม่สามารถบันทึกโปรไฟล์ได้"
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

  return toBase64(salt) + ":" +
         toBase64(new Uint8Array(bits));
}

async function verifyPassword(password, storedHash) {
  try {
    const parts = String(storedHash).split(":");

    if (parts.length !== 2) {
      return false;
    }

    const salt = fromBase64(parts[0]);
    const stored = fromBase64(parts[1]);

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

    const calculated = new Uint8Array(bits);

    if (calculated.length !== stored.length) {
      return false;
    }

    let difference = 0;

    for (let i = 0; i < calculated.length; i++) {
      difference |= calculated[i] ^ stored[i];
    }

    return difference === 0;

  } catch (error) {
    return false;
  }
}

function toBase64(bytes) {
  let binary = "";

  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
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
