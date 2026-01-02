const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

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

function ensureDataFile() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, '[]', 'utf8');
  }
}

function readMessages() {
  ensureDataFile();
  const raw = fs.readFileSync(DATA_FILE, 'utf8') || '[]';
  return JSON.parse(raw);
}

function writeMessages(messages) {
  ensureDataFile();
  fs.writeFileSync(DATA_FILE, JSON.stringify(messages, null, 2));
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
      body += chunk;
      if (body.length > MAX_BODY_SIZE) {
        reject(new Error('Payload too large'));
        req.destroy();
      }
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

function handleApi(req, res, url) {
  if (url.pathname !== '/api/messages') return false;

  if (req.method === 'OPTIONS') {
    sendJSON(res, 200, { ok: true });
    return true;
  }

  if (req.method === 'GET') {
    const messages = readMessages();
    sendJSON(res, 200, { messages });
    return true;
  }

  if (req.method === 'POST') {
    parseBody(req)
      .then(body => {
        const name = (body.name || '').trim();
        const email = (body.email || '').trim();
        const role = (body.role || 'guest').trim();
        const message = (body.message || '').trim();

        if (!name || !email || !message) {
          sendJSON(res, 400, { error: 'Name, email, and message are required.' });
          return;
        }

        const emailPattern = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
        if (!emailPattern.test(email)) {
          sendJSON(res, 400, { error: 'Please provide a valid email.' });
          return;
        }

        if (message.length > 1000) {
          sendJSON(res, 400, { error: 'Message is too long. Keep it under 1000 characters.' });
          return;
        }

        const messages = readMessages();
        const entry = {
          id: Date.now(),
          name,
          email,
          role,
          message,
          createdAt: new Date().toISOString()
        };

        messages.push(entry);
        writeMessages(messages);
        sendJSON(res, 201, { message: 'Saved', entry });
      })
      .catch(() => sendJSON(res, 400, { error: 'Invalid JSON payload.' }));

    return true;
  }

  sendJSON(res, 405, { error: 'Method not allowed' });
  return true;
}

function serveStatic(req, res, url) {
  const requestedPath = url.pathname === '/' ? '/index.html' : url.pathname;
  const safePath = path.normalize(path.join(PUBLIC_DIR, decodeURIComponent(requestedPath)));

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

  if (handleApi(req, res, url)) {
    return;
  }

  serveStatic(req, res, url);
});

server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
