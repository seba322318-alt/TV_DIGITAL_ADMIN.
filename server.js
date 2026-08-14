'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3000);
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'CAMBIA_ESTA_CLAVE_2026';
const SESSION_HOURS = Math.max(1, Number(process.env.SESSION_HOURS || 24));

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

const MAX_BODY = 1024 * 1024;

function nowIso() {
  return new Date().toISOString();
}

function uuid() {
  return crypto.randomUUID();
}

function randomToken() {
  return crypto.randomBytes(32).toString('hex');
}

function cleanText(value, max = 250) {
  return String(value ?? '').trim().slice(0, max);
}

function asInt(value, fallback, min = 1, max = 1000) {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n)
    ? Math.min(max, Math.max(min, n))
    : fallback;
}

function hashPassword(
  password,
  salt = crypto.randomBytes(16).toString('hex')
) {
  const hash = crypto
    .pbkdf2Sync(String(password), salt, 120000, 32, 'sha256')
    .toString('hex');

  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;

  const [salt, expected] = stored.split(':');

  const actual = crypto
    .pbkdf2Sync(String(password), salt, 120000, 32, 'sha256')
    .toString('hex');

  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(expected, 'hex');

  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function ensureDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });

  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(
      DB_FILE,
      JSON.stringify(
        {
          users: [],
          content: [],
          sessions: [],
          adminSessions: []
        },
        null,
        2
      )
    );
  }
}

function loadDb() {
  ensureDb();

  try {
    const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));

    db.users ||= [];
    db.content ||= [];
    db.sessions ||= [];
    db.adminSessions ||= [];

    return db;
  } catch (e) {
    throw new Error(`No se pudo leer ${DB_FILE}: ${e.message}`);
  }
}

function saveDb(db) {
  const tmp = `${DB_FILE}.tmp`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(db, null, 2)
  );

  fs.renameSync(tmp, DB_FILE);
}

function purgeSessions(db) {
  const now = Date.now();

  db.sessions = db.sessions.filter(
    s => new Date(s.expiresAt).getTime() > now
  );

  db.adminSessions = db.adminSessions.filter(
    s => new Date(s.expiresAt).getTime() > now
  );
}

function userDto(u) {
  return {
    id: u.id,
    name: u.name,
    username: u.username,
    role: u.role,
    status: u.status,
    expiresAt: u.expiresAt || null,
    maxDevices: u.maxDevices || 1,
    maxConcurrent: u.maxConcurrent || 1
  };
}

function contentDto(c) {
  return {
    id: c.id,
    type: c.type,
    title: c.title,
    description: c.description || null,
    posterUrl: c.posterUrl || null,
    logoUrl: c.logoUrl || null,
    streamUrl: c.streamUrl,
    year: c.year || null
  };
}

function isExpired(user) {
  return Boolean(
    user.expiresAt &&
    new Date(user.expiresAt).getTime() <= Date.now()
  );
}

function publicStatus(user) {
  if (user.status !== 'ACTIVE') {
    return user.status;
  }

  if (isExpired(user)) {
    return 'EXPIRED';
  }

  return 'ACTIVE';
}

function json(res, status, body) {
  const data = Buffer.from(
    JSON.stringify(body)
  );

  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': data.length,
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers':
      'Content-Type, Authorization',
    'Access-Control-Allow-Methods':
      'GET,POST,PATCH,DELETE,OPTIONS'
  });

  res.end(data);
}

function text(
  res,
  status,
  body,
  type = 'text/plain; charset=utf-8'
) {
  const data = Buffer.from(body);

  res.writeHead(status, {
    'Content-Type': type,
    'Content-Length': data.length,
    'Cache-Control': 'no-store'
  });

  res.end(data);
}

function readBody(req) {
  return new Promise(
    (resolve, reject) => {
      let total = 0;
      const chunks = [];

      req.on('data', chunk => {
        total += chunk.length;

        if (total > MAX_BODY) {
          reject(
            Object.assign(
              new Error('Body demasiado grande'),
              { status: 413 }
            )
          );

          req.destroy();
          return;
        }

        chunks.push(chunk);
      });

      req.on('end', () => {
        if (!chunks.length) {
          return resolve({});
        }

        try {
          resolve(
            JSON.parse(
              Buffer.concat(chunks)
                .toString('utf8')
            )
          );
        } catch {
          reject(
            Object.assign(
              new Error('JSON inválido'),
              { status: 400 }
            )
          );
        }
      });

      req.on('error', reject);
    }
  );
}

function bearer(req) {
  const h =
    req.headers.authorization || '';

  return h.startsWith('Bearer ')
    ? h.slice(7).trim()
    : '';
}

function requireUser(req, db) {
  const token = bearer(req);

  const session =
    db.sessions.find(
      s => s.token === token
    );

  if (!session) return null;

  const user =
    db.users.find(
      u => u.id === session.userId
    );

  if (
    !user ||
    publicStatus(user) !== 'ACTIVE'
  ) {
    return null;
  }

  session.lastSeenAt = nowIso();

  return {
    user,
    session
  };
}

function requireAdmin(req, db) {
  const token = bearer(req);

  return (
    db.adminSessions.find(
      s => s.token === token
    ) || null
  );
}

function routeMatch(pathname, re) {
  const m = pathname.match(re);

  return m || null;
}

function serveStatic(
  pathname,
  res
) {
  const file =
    pathname === '/'
      ? '/admin.html'
      : pathname;

  const safe =
    path
      .normalize(file)
      .replace(
        /^(\.\.[/\\])+/,
        ''
      );

  const full =
    path.join(
      PUBLIC_DIR,
      safe
    );

  if (
    !full.startsWith(PUBLIC_DIR) ||
    !fs.existsSync(full) ||
    fs.statSync(full).isDirectory()
  ) {
    return false;
  }

  const ext =
    path
      .extname(full)
      .toLowerCase();

  const types = {
    '.html':
      'text/html; charset=utf-8',

    '.js':
      'application/javascript; charset=utf-8',

    '.css':
      'text/css; charset=utf-8',

    '.png':
      'image/png',

    '.jpg':
      'image/jpeg',

    '.jpeg':
      'image/jpeg',

    '.svg':
      'image/svg+xml'
  };

  text(
    res,
    200,
    fs.readFileSync(full),
    types[ext] ||
      'application/octet-stream'
  );

  return true;
}

async function handler(
  req,
  res
) {
  if (
    req.method === 'OPTIONS'
  ) {
    return json(
      res,
      204,
      {}
    );
  }

  const url =
    new URL(
      req.url,
      `http://${req.headers.host || 'localhost'}`
    );

  const p =
    url.pathname;

  let db =
    loadDb();

  purgeSessions(db);

  try {

    // ==========================================
    // HEALTH
    // ==========================================

    if (
      req.method === 'GET' &&
      p === '/health'
    ) {
      return json(
        res,
        200,
        {
          ok: true,
          service:
            'TV DIGITAL API',
          time:
            nowIso()
        }
      );
    }

    // ==========================================
    // LOGIN CLIENTE
    // ==========================================

    if (
      req.method === 'POST' &&
      p === '/auth/login'
    ) {
      const b =
        await readBody(req);

      const username =
        cleanText(
          b.username,
          80
        ).toLowerCase();

      const password =
        String(
          b.password || ''
        );

      const deviceKey =
        cleanText(
          b.deviceKey,
          160
        );

      const deviceName =
        cleanText(
          b.deviceName ||
            'Android',
          120
        );

      if (
        !username ||
        !password ||
        !deviceKey
      ) {
        return json(
          res,
          400,
          {
            error:
              'username, password y deviceKey son obligatorios'
          }
        );
      }

      const user =
        db.users.find(
          u =>
            u.username
              .toLowerCase() ===
            username
        );

      if (
        !user ||
        !verifyPassword(
          password,
          user.passwordHash
        )
      ) {
        return json(
          res,
          401,
          {
            error:
              'Usuario o contraseña incorrectos'
          }
        );
      }

      const status =
        publicStatus(user);

      if (
        status !== 'ACTIVE'
      ) {
        return json(
          res,
          403,
          {
            error:
              status === 'EXPIRED'
                ? 'Cuenta vencida'
                : 'Cuenta suspendida'
          }
        );
      }

      user.devices ||= [];

      const known =
        user.devices.find(
          d =>
            d.deviceKey ===
            deviceKey
        );

      if (
        !known &&
        user.devices.length >=
          (user.maxDevices || 1)
      ) {
        return json(
          res,
          403,
          {
            error:
              'Límite de dispositivos alcanzado'
          }
        );
      }

      if (!known) {
        user.devices.push({
          deviceKey,
          deviceName,
          firstSeenAt:
            nowIso(),
          lastSeenAt:
            nowIso()
        });
      } else {
        known.deviceName =
          deviceName;

        known.lastSeenAt =
          nowIso();
      }

      const activeSessions =
        db.sessions.filter(
          s =>
            s.userId ===
            user.id
        );

      if (
        activeSessions.length >=
        (user.maxConcurrent || 1)
      ) {
        return json(
          res,
          403,
          {
            error:
              'Límite de conexiones simultáneas alcanzado. Cierra sesión en otro dispositivo.'
          }
        );
      }

      const token =
        randomToken();

      const sessionId =
        uuid();

      db.sessions.push({
        id:
          sessionId,

        token,

        userId:
          user.id,

        deviceKey,

        createdAt:
          nowIso(),

        lastSeenAt:
          nowIso(),

        expiresAt:
          new Date(
            Date.now() +
              SESSION_HOURS *
              3600000
          ).toISOString()
      });

      saveDb(db);

      return json(
        res,
        200,
        {
          token,

          user: {
            ...userDto(user),
            status:
              publicStatus(user)
          },

          sessionId
        }
      );
    }

    // ==========================================
    // PING
    // ==========================================

    if (
      req.method === 'POST' &&
      p === '/auth/ping'
    ) {
      const auth =
        requireUser(
          req,
          db
        );

      if (!auth) {
        return json(
          res,
          401,
          {
            ok: false,
            error:
              'Sesión inválida o cuenta no disponible'
          }
        );
      }

      saveDb(db);

      return json(
        res,
        200,
        {
          ok: true,
          serverTime:
            nowIso()
        }
      );
    }

    // ==========================================
    // LOGOUT CLIENTE
    // ==========================================

    if (
      req.method === 'POST' &&
      p === '/auth/logout'
    ) {
      const token =
        bearer(req);

      db.sessions =
        db.sessions.filter(
          s =>
            s.token !==
            token
        );

      saveDb(db);

      return json(
        res,
        200,
        {
          ok: true
        }
      );
    }

    // ==========================================
    // CONTENIDO PARA LA APK
    // ==========================================

    if (
      req.method === 'GET' &&
      p === '/content'
    ) {
      const auth =
        requireUser(
          req,
          db
        );

      if (!auth) {
        return json(
          res,
          401,
          {
            error:
              'No autorizado'
          }
        );
      }

      const type =
        cleanText(
          url.searchParams.get(
            'type'
          ) || '',
          30
        ).toUpperCase();

      let items =
        db.content.filter(
          c =>
            c.active !==
            false
        );

      if (type) {
        items =
          items.filter(
            c =>
              String(
                c.type
              ).toUpperCase() ===
              type
          );
      }

      saveDb(db);

      return json(
        res,
        200,
        items.map(
          contentDto
        )
      );
    }

    // ==========================================
    // LOGIN ADMINISTRADOR
    // ==========================================

    if (
      req.method === 'POST' &&
      p === '/admin/login'
    ) {
      const b =
        await readBody(req);

      if (
        String(
          b.username || ''
        ) !== ADMIN_USER ||
        String(
          b.password || ''
        ) !== ADMIN_PASSWORD
      ) {
        return json(
          res,
          401,
          {
            error:
              'Credenciales de administrador incorrectas'
          }
        );
      }

      const token =
        randomToken();

      db.adminSessions.push({
        id:
          uuid(),

        token,

        createdAt:
          nowIso(),

        expiresAt:
          new Date(
            Date.now() +
              12 *
              3600000
          ).toISOString()
      });

      saveDb(db);

      return json(
        res,
        200,
        {
          token,
          username:
            ADMIN_USER
        }
      );
    }

    // ==========================================
    // PROTEGER RUTAS ADMIN
    // ==========================================

    if (
      p.startsWith(
        '/admin/'
      ) &&
      p !== '/admin/login'
    ) {
      if (
        !requireAdmin(
          req,
          db
        )
      ) {
        return json(
          res,
          401,
          {
            error:
              'Administrador no autorizado'
          }
        );
      }
    }

    // ==========================================
    // ESTADÍSTICAS
    // ==========================================

    if (
      req.method === 'GET' &&
      p === '/admin/stats'
    ) {
      const users =
        db.users.map(
          u => ({
            ...u,
            computedStatus:
              publicStatus(u)
          })
        );

      return json(
        res,
        200,
        {
          users:
            users.length,

          active:
            users.filter(
              u =>
                u.computedStatus ===
                'ACTIVE'
            ).length,

          trials:
            users.filter(
              u =>
                u.role ===
                  'TRIAL' &&
                u.computedStatus ===
                  'ACTIVE'
            ).length,

          expired:
            users.filter(
              u =>
                u.computedStatus ===
                'EXPIRED'
            ).length,

          suspended:
            users.filter(
              u =>
                u.computedStatus ===
                'SUSPENDED'
            ).length,

          content:
            db.content.filter(
              c =>
                c.active !==
                false
            ).length,

          sessions:
            db.sessions.length
        }
      );
    }

    // ==========================================
    // LISTAR USUARIOS
    // ==========================================

    if (
      req.method === 'GET' &&
      p === '/admin/users'
    ) {
      return json(
        res,
        200,
        db.users.map(
          u => ({
            ...userDto(u),

            status:
              publicStatus(u),

            devices:
              u.devices || [],

            createdAt:
              u.createdAt
          })
        )
      );
    }

    // ==========================================
    // CREAR USUARIO
    // ==========================================

    if (
      req.method === 'POST' &&
      p === '/admin/users'
    ) {
      const b =
        await readBody(req);

      const username =
        cleanText(
          b.username,
          80
        ).toLowerCase();

      const password =
        String(
          b.password || ''
        );

      const name =
        cleanText(
          b.name ||
            username,
          120
        );

      const role =
        String(
          b.role ||
            'CLIENT'
        ).toUpperCase() ===
        'TRIAL'
          ? 'TRIAL'
          : 'CLIENT';

      const status =
        String(
          b.status ||
            'ACTIVE'
        ).toUpperCase() ===
        'SUSPENDED'
          ? 'SUSPENDED'
          : 'ACTIVE';

      if (
        !username ||
        password.length < 4
      ) {
        return json(
          res,
          400,
          {
            error:
              'Usuario obligatorio y contraseña mínima de 4 caracteres'
          }
        );
      }

      if (
        db.users.some(
          u =>
            u.username
              .toLowerCase() ===
            username
        )
      ) {
        return json(
          res,
          409,
          {
            error:
              'Ese usuario ya existe'
          }
        );
      }

      let expiresAt =
        b.expiresAt
          ? new Date(
              b.expiresAt
            ).toISOString()
          : null;

      if (
        !expiresAt &&
        role === 'TRIAL'
      ) {
        expiresAt =
          new Date(
            Date.now() +
              24 *
              3600000
          ).toISOString();
      }

      if (
        !expiresAt &&
        b.days
      ) {
        expiresAt =
          new Date(
            Date.now() +
              asInt(
                b.days,
                30,
                1,
                3650
              ) *
              86400000
          ).toISOString();
      }

      const user = {
        id:
          uuid(),

        name,

        username,

        passwordHash:
          hashPassword(
            password
          ),

        role,

        status,

        expiresAt,

        maxDevices:
          asInt(
            b.maxDevices,
            1,
            1,
            10
          ),

        maxConcurrent:
          asInt(
            b.maxConcurrent,
            1,
            1,
            10
          ),

        devices: [],

        createdAt:
          nowIso()
      };

      db.users.push(
        user
      );

      saveDb(db);

      return json(
        res,
        201,
        {
          ...userDto(
            user
          ),

          status:
            publicStatus(
              user
            )
        }
      );
    }

    // ==========================================
    // EDITAR / BORRAR USUARIO
    // ==========================================

    let m =
      routeMatch(
        p,
        /^\/admin\/users\/([^/]+)$/
      );

    if (
      m &&
      req.method === 'PATCH'
    ) {
      const user =
        db.users.find(
          u =>
            u.id ===
            m[1]
        );

      if (!user) {
        return json(
          res,
          404,
          {
            error:
              'Usuario no encontrado'
          }
        );
      }

      const b =
        await readBody(req);

      if (
        b.name !==
        undefined
      ) {
        user.name =
          cleanText(
            b.name,
            120
          );
      }

      if (
        b.username !==
        undefined
      ) {
        const un =
          cleanText(
            b.username,
            80
          ).toLowerCase();

        if (!un) {
          return json(
            res,
            400,
            {
              error:
                'Usuario inválido'
            }
          );
        }

        if (
          db.users.some(
            u =>
              u.id !==
                user.id &&
              u.username
                .toLowerCase() ===
                un
          )
        ) {
          return json(
            res,
            409,
            {
              error:
                'Ese usuario ya existe'
            }
          );
        }

        user.username =
          un;
      }

      if (
        b.password
      ) {
        user.passwordHash =
          hashPassword(
            String(
              b.password
            )
          );
      }

      if (
        b.role !==
        undefined
      ) {
        user.role =
          String(
            b.role
          ).toUpperCase() ===
          'TRIAL'
            ? 'TRIAL'
            : 'CLIENT';
      }

      if (
        b.status !==
        undefined
      ) {
        user.status =
          String(
            b.status
          ).toUpperCase() ===
          'SUSPENDED'
            ? 'SUSPENDED'
            : 'ACTIVE';
      }

      if (
        b.expiresAt !==
        undefined
      ) {
        user.expiresAt =
          b.expiresAt
            ? new Date(
                b.expiresAt
              ).toISOString()
            : null;
      }

      if (
        b.maxDevices !==
        undefined
      ) {
        user.maxDevices =
          asInt(
            b.maxDevices,
            1,
            1,
            10
          );
      }

      if (
        b.maxConcurrent !==
        undefined
      ) {
        user.maxConcurrent =
          asInt(
            b.maxConcurrent,
            1,
            1,
            10
          );
      }

      saveDb(db);

      return json(
        res,
        200,
        {
          ...userDto(
            user
          ),

          status:
            publicStatus(
              user
            ),

          devices:
            user.devices ||
            []
        }
      );
    }

    if (
      m &&
      req.method === 'DELETE'
    ) {
      const exists =
        db.users.some(
          u =>
            u.id ===
            m[1]
        );

      if (!exists) {
        return json(
          res,
          404,
          {
            error:
              'Usuario no encontrado'
          }
        );
      }

      db.users =
        db.users.filter(
          u =>
            u.id !==
            m[1]
        );

      db.sessions =
        db.sessions.filter(
          s =>
            s.userId !==
            m[1]
        );

      saveDb(db);

      return json(
        res,
        200,
        {
          ok: true
        }
      );
    }

    // ==========================================
    // EXTENDER SERVICIO
    // ==========================================

    m =
      routeMatch(
        p,
        /^\/admin\/users\/([^/]+)\/extend$/
      );

    if (
      m &&
      req.method === 'POST'
    ) {
      const user =
        db.users.find(
          u =>
            u.id ===
            m[1]
        );

      if (!user) {
        return json(
          res,
          404,
          {
            error:
              'Usuario no encontrado'
          }
        );
      }

      const b =
        await readBody(req);

      const days =
        asInt(
          b.days,
          30,
          1,
          3650
        );

      const base =
        user.expiresAt &&
        new Date(
          user.expiresAt
        ).getTime() >
          Date.now()

          ? new Date(
              user.expiresAt
            ).getTime()

          : Date.now();

      user.expiresAt =
        new Date(
          base +
            days *
            86400000
        ).toISOString();

      user.status =
        'ACTIVE';

      if (
        days > 1 &&
        user.role ===
          'TRIAL'
      ) {
        user.role =
          'CLIENT';
      }

      saveDb(db);

      return json(
        res,
        200,
        {
          ...userDto(
            user
          ),

          status:
            publicStatus(
              user
            )
        }
      );
    }

    // ==========================================
    // LIBERAR DISPOSITIVOS
    // ==========================================

    m =
      routeMatch(
        p,
        /^\/admin\/users\/([^/]+)\/reset-devices$/
      );

    if (
      m &&
      req.method === 'POST'
    ) {
      const user =
        db.users.find(
          u =>
            u.id ===
            m[1]
        );

      if (!user) {
        return json(
          res,
          404,
          {
            error:
              'Usuario no encontrado'
          }
        );
      }

      user.devices = [];

      db.sessions =
        db.sessions.filter(
          s =>
            s.userId !==
            user.id
        );

      saveDb(db);

      return json(
        res,
        200,
        {
          ok: true
        }
      );
    }

    // ==========================================
    // LISTAR CONTENIDO ADMIN
    // ==========================================

    if (
      req.method === 'GET' &&
      p === '/admin/content'
    ) {
      return json(
        res,
        200,
        db.content
      );
    }

    // ==========================================
    // CREAR CONTENIDO
    // ==========================================

    if (
      req.method === 'POST' &&
      p === '/admin/content'
    ) {
      const b =
        await readBody(req);

      const title =
        cleanText(
          b.title,
          180
        );

      const streamUrl =
        cleanText(
          b.streamUrl,
          2000
        );

      const allowed = [
        'TV',
        'MOVIE',
        'SERIES'
      ];

      const type =
        allowed.includes(
          String(
            b.type || ''
          ).toUpperCase()
        )
          ? String(
              b.type
            ).toUpperCase()
          : 'TV';

      if (
        !title ||
        !streamUrl
      ) {
        return json(
          res,
          400,
          {
            error:
              'Título y URL de reproducción son obligatorios'
          }
        );
      }

      const item = {
        id:
          uuid(),

        type,

        title,

        description:
          cleanText(
            b.description,
            1000
          ) || null,

        posterUrl:
          cleanText(
            b.posterUrl,
            2000
          ) || null,

        logoUrl:
          cleanText(
            b.logoUrl,
            2000
          ) || null,

        streamUrl,

        year:
          b.year
            ? asInt(
                b.year,
                new Date()
                  .getFullYear(),
                1900,
                2200
              )
            : null,

        active:
          b.active !== false,

        createdAt:
          nowIso()
      };

      db.content.push(
        item
      );

      saveDb(db);

      return json(
        res,
        201,
        item
      );
    }

    // ==========================================
    // EDITAR / BORRAR CONTENIDO
    // ==========================================

    m =
      routeMatch(
        p,
        /^\/admin\/content\/([^/]+)$/
      );

    if (
      m &&
      req.method === 'PATCH'
    ) {
      const item =
        db.content.find(
          c =>
            c.id ===
            m[1]
        );

      if (!item) {
        return json(
          res,
          404,
          {
            error:
              'Contenido no encontrado'
          }
        );
      }

      const b =
        await readBody(req);

      for (
        const k of [
          'title',
          'description',
          'posterUrl',
          'logoUrl',
          'streamUrl'
        ]
      ) {
        if (
          b[k] !==
          undefined
        ) {
          item[k] =
            cleanText(
              b[k],
              k ===
                'description'
                ? 1000
                : 2000
            ) || null;
        }
      }

      if (
        b.type !==
          undefined &&
        [
          'TV',
          'MOVIE',
          'SERIES'
        ].includes(
          String(
            b.type
          ).toUpperCase()
        )
      ) {
        item.type =
          String(
            b.type
          ).toUpperCase();
      }

      if (
        b.year !==
        undefined
      ) {
        item.year =
          b.year
            ? asInt(
                b.year,
                new Date()
                  .getFullYear(),
                1900,
                2200
              )
            : null;
      }

      if (
        b.active !==
        undefined
      ) {
        item.active =
          Boolean(
            b.active
          );
      }

      if (
        !item.title ||
        !item.streamUrl
      ) {
        return json(
          res,
          400,
          {
            error:
              'Título y URL son obligatorios'
          }
        );
      }

      saveDb(db);

      return json(
        res,
        200,
        item
      );
    }

    if (
      m &&
      req.method === 'DELETE'
    ) {
      if (
        !db.content.some(
          c =>
            c.id ===
            m[1]
        )
      ) {
        return json(
          res,
          404,
          {
            error:
              'Contenido no encontrado'
          }
        );
      }

      db.content =
        db.content.filter(
          c =>
            c.id !==
            m[1]
        );

      saveDb(db);

      return json(
        res,
        200,
        {
          ok: true
        }
      );
    }

    // ==========================================
    // LOGOUT ADMIN
    // ==========================================

    if (
      req.method === 'POST' &&
      p === '/admin/logout'
    ) {
      const token =
        bearer(req);

      db.adminSessions =
        db.adminSessions.filter(
          s =>
            s.token !==
            token
        );

      saveDb(db);

      return json(
        res,
        200,
        {
          ok: true
        }
      );
    }

    // ==========================================
    // PANEL WEB
    // ==========================================

    if (
      req.method === 'GET' &&
      serveStatic(
        p,
        res
      )
    ) {
      return;
    }

    return json(
      res,
      404,
      {
        error:
          'Ruta no encontrada'
      }
    );

  } catch (e) {

    console.error(e);

    return json(
      res,
      e.status || 500,
      {
        error:
          e.status
            ? e.message
            : 'Error interno del servidor'
      }
    );
  }
}

ensureDb();

const server =
  http.createServer(
    handler
  );

server.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log(
      `TV DIGITAL API escuchando en http://0.0.0.0:${PORT}`
    );

    console.log(
      `Panel administrador activo`
    );

    if (
      !process.env.ADMIN_PASSWORD
    ) {
      console.warn(
        'ADVERTENCIA: configura ADMIN_PASSWORD en Render.'
      );
    }
  }
);
