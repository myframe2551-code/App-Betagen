export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders()
      });
    }

    try {
      if (url.pathname === "/users" && request.method === "GET") {
        return await getUsers(env);
      }

      if (url.pathname === "/profile" && request.method === "GET") {
        return await getProfile(request, env);
      }

      if (url.pathname === "/profile" && request.method === "PUT") {
        return await updateProfile(request, env);
      }

      if (url.pathname === "/register" && request.method === "POST") {
        return await register(request, env);
      }

      if (url.pathname === "/login" && request.method === "POST") {
        return await login(request, env);
      }

      return json({
        success: false,
        message: "ไม่พบ API"
      }, 404);

    } catch (error) {
      return json({
        success: false,
        message: "เกิดข้อผิดพลาดของเซิร์ฟเวอร์"
      }, 500);
    }
  }
};

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,PUT,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  };
}

function json(data, status) {
  return new Response(
    JSON.stringify(data),
    {
      status: status || 200,
      headers: {
        "Content-Type": "application/json; charset=UTF-8",
        ...corsHeaders()
      }
    }
  );
}

async function getUsers(env) {
  const result = await env.DB.prepare(
    `SELECT id,nickname,username,age,gender,avatar,created_at
     FROM users
     ORDER BY id DESC`
  ).all();

  return json({
    success: true,
    users: result.results || []
  });
}

async function getProfile(request, env) {
  const url = new URL(request.url);

  const username =
    url.searchParams.get("username");

  if (!username) {
    return json({
      success: false,
      message: "ไม่พบชื่อผู้ใช้"
    }, 400);
  }

  const user =
    await env.DB.prepare(
      `SELECT id,nickname,username,age,gender,avatar,created_at
       FROM users
       WHERE username = ?`
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
  });
}

async function updateProfile(request, env) {
  const data =
    await request.json();

  const username =
    String(data.username || "").trim();

  const nickname =
    String(data.nickname || "").trim();

  const avatar =
    String(data.avatar || "");

  if (!username) {
    return json({
      success: false,
      message: "ไม่พบชื่อผู้ใช้"
    }, 400);
  }

  if (!nickname) {
    return json({
      success: false,
      message: "กรุณากรอกชื่อเล่น"
    }, 400);
  }

  await env.DB.prepare(
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

  const user =
    await env.DB.prepare(
      `SELECT id,nickname,username,age,gender,avatar,created_at
       FROM users
       WHERE username = ?`
    )
    .bind(username)
    .first();

  return json({
    success: true,
    message: "บันทึกข้อมูลสำเร็จ",
    user: user
  });
}

async function register(request, env) {
  const data =
    await request.json();

  const nickname =
    String(data.nickname || "").trim();

  const username =
    String(data.username || "").trim();

  const age =
    String(data.age || "").trim();

  const gender =
    String(data.gender || "").trim();

  const phone =
    String(data.phone || "").trim();

  const password =
    String(data.password || "");

  if (!nickname ||
      !username ||
      !age ||
      !gender ||
      !phone ||
      !password) {

    return json({
      success: false,
      message: "กรุณากรอกข้อมูลให้ครบ"
    }, 400);
  }

  const existing =
    await env.DB.prepare(
      `SELECT id
       FROM users
       WHERE username = ?`
    )
    .bind(username)
    .first();

  if (existing) {
    return json({
      success: false,
      message: "ชื่อผู้ใช้นี้มีอยู่แล้ว"
    }, 400);
  }

  const passwordHash =
    await hashPassword(password);

  const createdAt =
    new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO users
     (nickname,username,age,gender,phone,password_hash,avatar,created_at)
     VALUES (?,?,?,?,?,?,?,?)`
  )
  .bind(
    nickname,
    username,
    age,
    gender,
    phone,
    passwordHash,
    "",
    createdAt
  )
  .run();

  return json({
    success: true,
    message: "สมัครสมาชิกสำเร็จ"
  });
}

async function login(request, env) {
  const data =
    await request.json();

  const username =
    String(data.username || "").trim();

  const password =
    String(data.password || "");

  if (!username || !password) {
    return json({
      success: false,
      message: "กรุณากรอกชื่อผู้ใช้และรหัสผ่าน"
    }, 400);
  }

  const user =
    await env.DB.prepare(
      `SELECT id,nickname,username,age,gender,avatar,password_hash,created_at
       FROM users
       WHERE username = ?`
    )
    .bind(username)
    .first();

  if (!user) {
    return json({
      success: false,
      message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"
    }, 401);
  }

  const valid =
    await verifyPassword(
      password,
      user.password_hash
    );

  if (!valid) {
    return json({
      success: false,
      message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"
    }, 401);
  }

  delete user.password_hash;

  return json({
    success: true,
    message: "เข้าสู่ระบบสำเร็จ",
    user: user
  });
}

async function hashPassword(password) {
  const encoder =
    new TextEncoder();

  const salt =
    crypto.getRandomValues(
      new Uint8Array(16)
    );

  const key =
    await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      {
        name: "PBKDF2"
      },
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      key,
      256
    );

  return (
    "pbkdf2$100000$" +
    toBase64(salt) +
    "$" +
    toBase64(
      new Uint8Array(bits)
    )
  );
}

async function verifyPassword(
  password,
  stored
) {
  try {

    const parts =
      stored.split("$");

    if (parts.length !== 4) {
      return false;
    }

    const iterations =
      parseInt(parts[1], 10);

    const salt =
      fromBase64(parts[2]);

    const expected =
      fromBase64(parts[3]);

    const encoder =
      new TextEncoder();

    const key =
      await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        {
          name: "PBKDF2"
        },
        false,
        ["deriveBits"]
      );

    const bits =
      await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: iterations,
          hash: "SHA-256"
        },
        key,
        256
      );

    const actual =
      new Uint8Array(bits);

    if (actual.length !== expected.length) {
      return false;
    }

    let difference = 0;

    for (let i = 0;
         i < actual.length;
         i++) {

      difference |=
        actual[i] ^ expected[i];
    }

    return difference === 0;

  } catch (e) {

    return false;
  }
}

function toBase64(bytes) {
  let binary = "";

  for (let i = 0;
       i < bytes.length;
       i++) {

    binary +=
      String.fromCharCode(
        bytes[i]
      );
  }

  return btoa(binary);
}

function fromBase64(value) {
  const binary =
    atob(value);

  const bytes =
    new Uint8Array(
      binary.length
    );

  for (let i = 0;
       i < binary.length;
       i++) {

    bytes[i] =
      binary.charCodeAt(i);
  }

  return bytes;
    }
