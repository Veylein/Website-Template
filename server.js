const http = require('http');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { URL } = require('url');
const { randomUUID, createHash } = require('crypto');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = __dirname;
const PUBLIC_DIR_RESOLVED = path.resolve(PUBLIC_DIR).toLowerCase();
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'messages.json');
const STORE_PATHS = {
  messages: DATA_FILE,
  users: path.join(DATA_DIR, 'users.json'),
  cards: path.join(DATA_DIR, 'cards.json'),
  logs: path.join(DATA_DIR, 'logs.json'),
  sessions: path.join(DATA_DIR, 'sessions.json')
};
const MAX_BODY_SIZE = 1e6; // 1MB safety limit
const SESSION_MAX_AGE_MS = 1000 * 60 * 60 * 24 * 7; // 7 days
const APP_SECRET = process.env.APP_SECRET || 'dev-secret-change-me';
const EMAIL_REGEX = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function sanitize(value) {
  return String(value ?? '')
    .trim()
    .replace(/[&<>"']/g, (ch) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    })[ch]);
}

async function ensureDataFile(filePath, fallback = '[]') {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  try {
    await fsp.access(filePath);
  } catch {
    await fsp.writeFile(filePath, fallback, 'utf8');
  }
}

async function readStore(key, fallback = []) {
  const filePath = STORE_PATHS[key];
  if (!filePath) throw new Error(`Unknown store: ${key}`);
  await ensureDataFile(filePath, JSON.stringify(fallback));
  const raw = await fsp.readFile(filePath, 'utf8');
  const safe = raw && raw.trim() ? raw : JSON.stringify(fallback);
  try {
    return JSON.parse(safe);
  } catch {
    await fsp.writeFile(filePath, JSON.stringify(fallback), 'utf8');
    return Array.isArray(fallback) ? [] : { ...fallback };
  }
}

const writeQueues = new Map();

async function writeStore(key, value) {
  const filePath = STORE_PATHS[key];
  if (!filePath) throw new Error(`Unknown store: ${key}`);
  await ensureDataFile(filePath, JSON.stringify(Array.isArray(value) ? [] : {}));
  const currentQueue = writeQueues.get(key) || Promise.resolve();
  const nextQueue = currentQueue.then(() =>
    fsp.writeFile(filePath, JSON.stringify(value, null, 2))
  );
  writeQueues.set(key, nextQueue);
  return nextQueue;
}

function sendJSON(res, statusCode, payload) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Credentials': 'true'
  });
  res.end(JSON.stringify(payload));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let aborted = false;

    req.on('data', chunk => {
      if (aborted) return;
      if (body.length + chunk.length > MAX_BODY_SIZE) {
        aborted = true;
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      body += chunk;
    });

    req.on('end', () => {
      if (aborted) return;
      try {
        const parsed = body ? JSON.parse(body) : {};
        resolve(parsed);
      } catch (err) {
        reject(err);
      }
    });

    req.on('error', reject);
  });
}

function parseCookies(cookieHeader = '') {
  return cookieHeader.split(';').reduce((acc, part) => {
    const [key, ...rest] = part.trim().split('=');
    if (!key) return acc;
    acc[key] = decodeURIComponent(rest.join('='));
    return acc;
  }, {});
}

function hashPassword(password, salt) {
  return createHash('sha256').update(`${password}:${salt}:${APP_SECRET}`).digest('hex');
}

function scrubUser(user) {
  if (!user) return null;
  const { passwordHash, passwordSalt, resetToken, ...clean } = user;
  return clean;
}

async function logAction(userId, action, detail = '') {
  const logs = await readStore('logs');
  logs.push({
    id: randomUUID(),
    userId: userId || 'anonymous',
    action,
    detail,
    timestamp: new Date().toISOString()
  });
  if (logs.length > 500) {
    logs.splice(0, logs.length - 500);
  }
  await writeStore('logs', logs);
}

async function getSession(req) {
  const cookies = parseCookies(req.headers.cookie || '');
  const authHeader = req.headers.authorization || '';
  const token = cookies.sessionId || (authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '');
  if (!token) return null;

  const sessions = await readStore('sessions');
  const session = sessions.find((s) => s.id === token);
  if (!session) return null;

  if (new Date(session.expiresAt).getTime() < Date.now()) {
    await writeStore('sessions', sessions.filter((s) => s.id !== token));
    return null;
  }

  const users = await readStore('users');
  const user = users.find((u) => u.id === session.userId);
  if (!user) return null;

  return { session, user };
}

async function requireAuth(req, res) {
  const auth = await getSession(req);
  if (!auth) {
    sendJSON(res, 401, { error: 'Authentication required' });
    return null;
  }
  return auth;
}

async function createSession(userId) {
  const sessions = await readStore('sessions');
  const expiresAt = new Date(Date.now() + SESSION_MAX_AGE_MS).toISOString();
  const session = { id: randomUUID(), userId, expiresAt };
  sessions.push(session);
  await writeStore('sessions', sessions);
  return session;
}

function setSessionCookie(res, sessionId, maxAgeMs = SESSION_MAX_AGE_MS) {
  res.setHeader(
    'Set-Cookie',
    `sessionId=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(maxAgeMs / 1000)}`
  );
}

async function handleApi(req, res, url) {
  if (!url.pathname.startsWith('/api/')) return false;

  if (req.method === 'OPTIONS') {
    sendJSON(res, 200, { ok: true });
    return true;
  }

  const pathName = url.pathname;

  if (pathName === '/api/messages') {
    if (req.method === 'GET') {
      const messages = await readStore('messages');
      sendJSON(res, 200, { messages });
      return true;
    }

    if (req.method === 'POST') {
      try {
        const body = await parseBody(req);
        const name = sanitize(body.name);
        const email = sanitize(body.email);
        const role = sanitize(body.role || 'guest');
        const message = sanitize(String(body.message ?? ''));

        if (!name || !email || !message) {
          sendJSON(res, 400, { error: 'Name, email, and message are required.' });
          return true;
        }

        if (!EMAIL_REGEX.test(email)) {
          sendJSON(res, 400, { error: 'Please provide a valid email.' });
          return true;
        }

        if (message.length > 1000) {
          sendJSON(res, 400, { error: 'Message is too long. Keep it under 1000 characters.' });
          return true;
        }

        const messages = await readStore('messages');
        const entry = {
          id: randomUUID(),
          name,
          email,
          role,
          message,
          createdAt: new Date().toISOString()
        };

        messages.push(entry);
        await writeStore('messages', messages);
        await logAction(null, 'message.create', `${email} submitted message`);
        sendJSON(res, 201, { message: 'Saved', entry });
      } catch (err) {
        sendJSON(res, 400, { error: 'Invalid JSON payload.' });
      }

      return true;
    }

    sendJSON(res, 405, { error: 'Method not allowed' });
    return true;
  }

  if (pathName === '/api/auth/signup' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const email = sanitize(body.email).toLowerCase();
      const password = String(body.password || '');
      const name = sanitize(body.name || 'New User');
      const theme = sanitize(body.theme || 'dark');

      if (!EMAIL_REGEX.test(email) || password.length < 6) {
        sendJSON(res, 400, { error: 'Valid email and password (6+ chars) required.' });
        return true;
      }

      const users = await readStore('users');
      if (users.find((u) => u.email === email)) {
        sendJSON(res, 409, { error: 'Account already exists. Please log in.' });
        return true;
      }

      const passwordSalt = randomUUID();
      const passwordHash = hashPassword(password, passwordSalt);
      const isAdmin = users.length === 0;
      const user = {
        id: randomUUID(),
        email,
        name,
        role: isAdmin ? 'admin' : 'user',
        theme,
        passwordSalt,
        passwordHash,
        verified: false,
        settings: { theme, accent: '#38bdf8', font: 'system', dashboardLayout: 'grid' },
        progress: {},
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      users.push(user);
      await writeStore('users', users);
      const session = await createSession(user.id);
      setSessionCookie(res, session.id);
      await logAction(user.id, 'auth.signup', `${email} created account`);
      sendJSON(res, 201, { user: scrubUser(user) });
    } catch (err) {
      sendJSON(res, 400, { error: 'Invalid signup payload.' });
    }
    return true;
  }

  if (pathName === '/api/auth/login' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const email = sanitize(body.email).toLowerCase();
      const password = String(body.password || '');
      const users = await readStore('users');
      const user = users.find((u) => u.email === email);

      if (!user || hashPassword(password, user.passwordSalt) !== user.passwordHash) {
        sendJSON(res, 401, { error: 'Invalid credentials' });
        return true;
      }

      const session = await createSession(user.id);
      setSessionCookie(res, session.id);
      await logAction(user.id, 'auth.login', `${email} logged in`);
      sendJSON(res, 200, { user: scrubUser(user) });
    } catch (err) {
      sendJSON(res, 400, { error: 'Invalid login payload.' });
    }
    return true;
  }

  if (pathName === '/api/auth/logout' && req.method === 'POST') {
    const auth = await getSession(req);
    if (auth?.session) {
      const sessions = await readStore('sessions');
      await writeStore('sessions', sessions.filter((s) => s.id !== auth.session.id));
      await logAction(auth.user.id, 'auth.logout', `${auth.user.email} logged out`);
    }
    setSessionCookie(res, '', 0);
    sendJSON(res, 200, { ok: true });
    return true;
  }

  if (pathName === '/api/auth/me' && req.method === 'GET') {
    const auth = await getSession(req);
    if (!auth) {
      sendJSON(res, 200, { user: null });
      return true;
    }
    sendJSON(res, 200, { user: scrubUser(auth.user) });
    return true;
  }

  if (pathName === '/api/auth/request-reset' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const email = sanitize(body.email).toLowerCase();
      const users = await readStore('users');
      const user = users.find((u) => u.email === email);
      if (user) {
        user.resetToken = randomUUID();
        user.resetRequestedAt = new Date().toISOString();
        await writeStore('users', users);
        await logAction(user.id, 'auth.reset.request', `${email} requested password reset`);
      }
      sendJSON(res, 200, { ok: true });
    } catch {
      sendJSON(res, 400, { error: 'Invalid payload.' });
    }
    return true;
  }

  if (pathName === '/api/auth/reset' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const token = sanitize(body.token);
      const password = String(body.password || '');
      const users = await readStore('users');
      const user = users.find((u) => u.resetToken === token);
      if (!user) {
        sendJSON(res, 400, { error: 'Invalid or expired token.' });
        return true;
      }
      if (password.length < 6) {
        sendJSON(res, 400, { error: 'Password must be at least 6 characters.' });
        return true;
      }
      const passwordSalt = randomUUID();
      user.passwordSalt = passwordSalt;
      user.passwordHash = hashPassword(password, passwordSalt);
      delete user.resetToken;
      delete user.resetRequestedAt;
      user.updatedAt = new Date().toISOString();
      await writeStore('users', users);
      await logAction(user.id, 'auth.reset.complete', `${user.email} reset password`);
      sendJSON(res, 200, { ok: true });
    } catch {
      sendJSON(res, 400, { error: 'Invalid payload.' });
    }
    return true;
  }

  if (pathName === '/api/auth/verify' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const email = sanitize(body.email).toLowerCase();
      const users = await readStore('users');
      const user = users.find((u) => u.email === email);
      if (user) {
        user.verified = true;
        user.updatedAt = new Date().toISOString();
        await writeStore('users', users);
        await logAction(user.id, 'auth.verify', `${email} verified`);
      }
      sendJSON(res, 200, { ok: true });
    } catch {
      sendJSON(res, 400, { error: 'Invalid payload.' });
    }
    return true;
  }

  if (pathName === '/api/me/settings') {
    const auth = await requireAuth(req, res);
    if (!auth) return true;
    const users = await readStore('users');
    const user = users.find((u) => u.id === auth.user.id);
    if (!user) {
      sendJSON(res, 404, { error: 'User not found' });
      return true;
    }

    if (req.method === 'GET') {
      sendJSON(res, 200, { settings: user.settings || {}, progress: user.progress || {} });
      return true;
    }

    if (req.method === 'PUT') {
      try {
        const body = await parseBody(req);
        user.settings = {
          ...user.settings,
          theme: body.settings?.theme || user.settings?.theme || 'dark',
          accent: body.settings?.accent || user.settings?.accent || '#38bdf8',
          font: body.settings?.font || user.settings?.font || 'system',
          dashboardLayout: body.settings?.dashboardLayout || user.settings?.dashboardLayout || 'grid'
        };
        user.progress = { ...user.progress, ...(body.progress || {}) };
        user.updatedAt = new Date().toISOString();
        await writeStore('users', users);
        await logAction(user.id, 'user.settings.update', 'User updated settings');
        sendJSON(res, 200, { settings: user.settings, progress: user.progress });
      } catch {
        sendJSON(res, 400, { error: 'Invalid payload.' });
      }
      return true;
    }

    sendJSON(res, 405, { error: 'Method not allowed' });
    return true;
  }

  if (pathName === '/api/cards' || pathName.startsWith('/api/cards/')) {
    const auth = await requireAuth(req, res);
    if (!auth) return true;
    const usersCards = await readStore('cards');
    const userCards = usersCards.filter((c) => c.ownerId === auth.user.id);

    if (req.method === 'GET') {
      sendJSON(res, 200, { cards: userCards });
      return true;
    }

    if (req.method === 'POST') {
      try {
        const body = await parseBody(req);
        const title = sanitize(body.title || 'Untitled');
        const content = sanitize(body.content || '');
        const layout = sanitize(body.layout || 'default');
        const card = {
          id: randomUUID(),
          title,
          content,
          layout,
          ownerId: auth.user.id,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };
        usersCards.push(card);
        await writeStore('cards', usersCards);
        await logAction(auth.user.id, 'card.create', `Created card ${card.id}`);
        sendJSON(res, 201, { card });
      } catch {
        sendJSON(res, 400, { error: 'Invalid payload.' });
      }
      return true;
    }

    const id = pathName.split('/')[3];
    const card = usersCards.find((c) => c.id === id && c.ownerId === auth.user.id);
    if (!card) {
      sendJSON(res, 404, { error: 'Card not found' });
      return true;
    }

    if (req.method === 'PUT') {
      try {
        const body = await parseBody(req);
        card.title = sanitize(body.title ?? card.title);
        card.content = sanitize(body.content ?? card.content);
        card.layout = sanitize(body.layout ?? card.layout);
        card.updatedAt = new Date().toISOString();
        await writeStore('cards', usersCards);
        await logAction(auth.user.id, 'card.update', `Updated card ${card.id}`);
        sendJSON(res, 200, { card });
      } catch {
        sendJSON(res, 400, { error: 'Invalid payload.' });
      }
      return true;
    }

    if (req.method === 'DELETE') {
      await writeStore('cards', usersCards.filter((c) => !(c.id === id && c.ownerId === auth.user.id)));
      await logAction(auth.user.id, 'card.delete', `Deleted card ${id}`);
      sendJSON(res, 204, {});
      return true;
    }

    sendJSON(res, 405, { error: 'Method not allowed' });
    return true;
  }

  if (pathName === '/api/admin/logs' && req.method === 'GET') {
    const auth = await requireAuth(req, res);
    if (!auth) return true;
    if (auth.user.role !== 'admin') {
      sendJSON(res, 403, { error: 'Admin access required' });
      return true;
    }
    const logs = await readStore('logs');
    sendJSON(res, 200, { logs: logs.slice(-200).reverse() });
    return true;
  }

  if (pathName === '/api/live/notifications' && req.method === 'GET') {
    const auth = await requireAuth(req, res);
    if (!auth) return true;
    const since = Number(url.searchParams.get('since') || 0);
    const logs = await readStore('logs');
    const filtered = logs.filter(
      (l) =>
        (l.userId === auth.user.id || l.userId === 'anonymous') &&
        new Date(l.timestamp).getTime() > since
    );
    sendJSON(res, 200, { events: filtered, now: Date.now() });
    return true;
  }

  sendJSON(res, 404, { error: 'Not found' });
  return true;
}

function serveStatic(req, res, url) {
  const requestedPath = url.pathname === '/' ? 'index.html' : url.pathname;
  const decoded = decodeURIComponent(requestedPath);
  const normalized = path.normalize(decoded).replace(/^[/\\]+/, '');
  if (normalized.startsWith('..')) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Forbidden');
    return;
  }
  const safePath = path.resolve(path.join(PUBLIC_DIR, normalized));
  if (!safePath.toLowerCase().startsWith(PUBLIC_DIR_RESOLVED)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Forbidden');
    return;
  }

  if (!safePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Forbidden');
    return;
  }

  fs.readFile(safePath, (err, data) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Not Found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Server Error');
      }
      return;
    }

    const ext = path.extname(safePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  Promise.resolve(handleApi(req, res, url))
    .then((handled) => {
      if (handled) return;
      serveStatic(req, res, url);
    })
    .catch((err) => {
      console.error('Server error', err);
      res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'Server error' }));
    });
});

server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
