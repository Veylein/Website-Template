const http = require('http');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { URL } = require('url');
const { randomUUID } = require('crypto');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = __dirname;
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'messages.json');
const MAX_BODY_SIZE = 1e6; // 1MB safety limit

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

async function ensureDataFile() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  try {
    await fsp.access(DATA_FILE);
  } catch {
    await fsp.writeFile(DATA_FILE, '[]', 'utf8');
  }
}

async function readMessages() {
  await ensureDataFile();
  const raw = await fsp.readFile(DATA_FILE, 'utf8');
  const safe = raw && raw.trim() ? raw : '[]';
  try {
    return JSON.parse(safe);
  } catch {
    await fsp.writeFile(DATA_FILE, '[]', 'utf8');
    return [];
  }
}

let writeQueue = Promise.resolve();

async function writeMessages(messages) {
  await ensureDataFile();
  writeQueue = writeQueue.then(() =>
    fsp.writeFile(DATA_FILE, JSON.stringify(messages, null, 2))
  );
  return writeQueue;
}

function sendJSON(res, statusCode, payload) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
  });
  res.end(JSON.stringify(payload));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';

    req.on('data', chunk => {
      if (body.length + chunk.length > MAX_BODY_SIZE) {
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      body += chunk;
    });

    req.on('end', () => {
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

async function handleApi(req, res, url) {
  if (url.pathname !== '/api/messages') return false;

  if (req.method === 'OPTIONS') {
    sendJSON(res, 200, { ok: true });
    return true;
  }

  if (req.method === 'GET') {
    const messages = await readMessages();
    sendJSON(res, 200, { messages });
    return true;
  }

  if (req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const rawMessage = String(body.message ?? '');
      if (rawMessage.length > 1000) {
        sendJSON(res, 400, { error: 'Message is too long. Keep it under 1000 characters.' });
        return true;
      }

      const name = sanitize(body.name);
      const email = sanitize(body.email);
      const role = sanitize(body.role || 'guest');
      const message = sanitize(rawMessage);

      if (!name || !email || !message) {
        sendJSON(res, 400, { error: 'Name, email, and message are required.' });
        return true;
      }

      const emailPattern = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
      if (!emailPattern.test(email)) {
        sendJSON(res, 400, { error: 'Please provide a valid email.' });
        return true;
      }

      const messages = await readMessages();
      const entry = {
        id: randomUUID(),
        name,
        email,
        role,
        message,
        createdAt: new Date().toISOString()
      };

      messages.push(entry);
      await writeMessages(messages);
      sendJSON(res, 201, { message: 'Saved', entry });
    } catch (err) {
      sendJSON(res, 400, { error: 'Invalid JSON payload.' });
    }

    return true;
  }

  sendJSON(res, 405, { error: 'Method not allowed' });
  return true;
}

function serveStatic(req, res, url) {
  const requestedPath = url.pathname === '/' ? '/index.html' : url.pathname;
  const safePath = path.resolve(PUBLIC_DIR, '.' + decodeURIComponent(requestedPath));

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
