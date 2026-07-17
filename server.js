// Handy-Mail – Hosting-Version (ein Server, überall lauffähig)
//
// Besonderheit: der Server SPEICHERT NICHTS. Deine Konten/Passwörter liegen nur
// in deinem Browser (localStorage) und werden pro Anfrage über HTTPS mitgeschickt,
// nur benutzt, um kurz die IMAP-Verbindung aufzubauen. Dadurch läuft die App auch
// auf Gratis-Hostern ohne dauerhaften Speicher problemlos.

import express from 'express';
import { ImapFlow } from 'imapflow';
import { simpleParser } from 'mailparser';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8080;

const app = express();
app.use(express.json({ limit: '1mb' }));

// ---------------------------------------------------------------------------
// Benutzer-Anmeldung (Registrieren + Login)
// Nutzer liegen in users.json neben dem Server; Passwörter nur als scrypt-Hash.
// Tokens sind HMAC-signiert und überleben so auch einen Server-Neustart.
// ---------------------------------------------------------------------------
const USERS_FILE = path.join(process.env.DATA_DIR || __dirname, 'users.json');
const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 Tage

function loadUserDB() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch { return { secret: crypto.randomBytes(32).toString('hex'), users: [] }; }
}
function saveUserDB() {
  try { fs.writeFileSync(USERS_FILE, JSON.stringify(userDB, null, 2)); }
  catch (err) { console.error('users.json konnte nicht gespeichert werden:', err.message); }
}
const userDB = loadUserDB();
if (!userDB.secret) { userDB.secret = crypto.randomBytes(32).toString('hex'); }
if (!Array.isArray(userDB.users)) { userDB.users = []; }

function hashPassword(pass, salt) {
  return crypto.scryptSync(pass, salt, 64).toString('hex');
}
function signToken(userId) {
  const payload = Buffer.from(JSON.stringify({ uid: userId, exp: Date.now() + TOKEN_TTL_MS })).toString('base64url');
  const sig = crypto.createHmac('sha256', userDB.secret).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', userDB.secret).update(payload).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data.uid || data.exp < Date.now()) return null;
    return userDB.users.find((u) => u.id === data.uid) || null;
  } catch { return null; }
}
function publicUser(u) { return { id: u.id, name: u.name, email: u.email }; }
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const user = verifyToken(auth.startsWith('Bearer ') ? auth.slice(7) : null);
  if (!user) return res.status(401).json({ error: 'Nicht angemeldet.' });
  req.user = user;
  next();
}

app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body || {};
  const mail = String(email || '').trim().toLowerCase();
  if (!mail || !password) return res.status(400).json({ error: 'E-Mail und Passwort sind nötig.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) return res.status(400).json({ error: 'Bitte eine gültige E-Mail-Adresse angeben.' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Das Passwort braucht mindestens 6 Zeichen.' });
  if (userDB.users.some((u) => u.email === mail)) return res.status(409).json({ error: 'Diese E-Mail ist bereits registriert – bitte anmelden.' });
  const salt = crypto.randomBytes(16).toString('hex');
  const user = {
    id: crypto.randomUUID(),
    name: String(name || '').trim() || mail.split('@')[0],
    email: mail,
    salt,
    hash: hashPassword(String(password), salt),
    createdAt: new Date().toISOString(),
  };
  userDB.users.push(user);
  saveUserDB();
  res.json({ token: signToken(user.id), user: publicUser(user) });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const mail = String(email || '').trim().toLowerCase();
  const user = userDB.users.find((u) => u.email === mail);
  if (!user || !password) return res.status(401).json({ error: 'E-Mail oder Passwort ist falsch.' });
  const attempt = Buffer.from(hashPassword(String(password), user.salt));
  const stored = Buffer.from(user.hash);
  if (attempt.length !== stored.length || !crypto.timingSafeEqual(attempt, stored)) {
    return res.status(401).json({ error: 'E-Mail oder Passwort ist falsch.' });
  }
  res.json({ token: signToken(user.id), user: publicUser(user) });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json(publicUser(req.user));
});

// ---------------------------------------------------------------------------
// IMAP-Konten pro Benutzer (liegen beim Benutzer in users.json,
// Passwörter verschlüsselt mit AES-256-GCM, damit sie nicht im Klartext stehen)
// ---------------------------------------------------------------------------
function accountKey() {
  return crypto.createHash('sha256').update('accounts:' + userDB.secret).digest();
}
function encryptSecret(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', accountKey(), iv);
  const data = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
  return { iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), data: data.toString('hex') };
}
function decryptSecret(enc) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', accountKey(), Buffer.from(enc.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(enc.tag, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(enc.data, 'hex')), decipher.final()]).toString('utf8');
}
function userAccounts(u) { if (!Array.isArray(u.accounts)) u.accounts = []; return u.accounts; }
function accountPublic(a) {
  return { id: a.id, label: a.label, email: a.email, host: a.host, port: a.port, secure: a.secure };
}
function accountFull(a) {
  return { ...accountPublic(a), user: a.user, pass: decryptSecret(a.passEnc) };
}
function buildAccount({ label, email, user, pass, host, port, secure }) {
  return {
    id: crypto.randomUUID(),
    label: String(label || '').trim() || user,
    email: String(email || user).trim(),
    host: String(host).trim(),
    port: Number(port) || 993,
    secure: secure !== false,
    user: String(user).trim(),
    passEnc: encryptSecret(pass),
  };
}

app.get('/api/accounts', requireAuth, (req, res) => {
  res.json(userAccounts(req.user).map(accountPublic));
});

// Konto hinzufügen: Verbindung wird erst getestet, dann gespeichert
app.post('/api/accounts', requireAuth, async (req, res) => {
  const { label, user, pass, host, port } = req.body || {};
  if (!user || !pass || !host) return res.status(400).json({ error: 'Host, Benutzer und Passwort nötig.' });
  const client = clientFor({ host, port, secure: true, user, pass });
  try {
    await client.connect();
    await client.logout();
  } catch (err) {
    try { await client.logout(); } catch {}
    return res.status(401).json({ error: 'Anmeldung fehlgeschlagen: ' + err.message });
  }
  const rec = buildAccount({ label, user, pass, host, port, secure: true });
  userAccounts(req.user).push(rec);
  saveUserDB();
  res.json(accountPublic(rec));
});

// Einmalige Übernahme früher im Browser gespeicherter Konten
app.post('/api/accounts/import', requireAuth, (req, res) => {
  const list = Array.isArray(req.body?.accounts) ? req.body.accounts : [];
  const accounts = userAccounts(req.user);
  let added = 0;
  for (const a of list) {
    if (!a || !a.user || !a.pass || !a.host) continue;
    if (accounts.some((x) => x.user === a.user && x.host === a.host)) continue;
    accounts.push(buildAccount(a));
    added++;
  }
  if (added) saveUserDB();
  res.json({ added, accounts: accounts.map(accountPublic) });
});

app.delete('/api/accounts/:id', requireAuth, (req, res) => {
  const accounts = userAccounts(req.user);
  const idx = accounts.findIndex((a) => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Konto nicht gefunden.' });
  accounts.splice(idx, 1);
  saveUserDB();
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Kategorien + automatische Erkennung
// ---------------------------------------------------------------------------
const CATEGORIES = [
  { id: 'inbox',     name: 'Posteingang',        icon: '📥', system: true },
  { id: 'unpaid',    name: 'Noch nicht bezahlt', icon: '💳',
    keywords: ['rechnung','invoice','mahnung','zahlung','zahlungserinnerung','offener betrag','fällig','faellig','payment due','überweisung','ueberweisung','bezahlen','unpaid','outstanding'] },
  { id: 'orders',    name: 'Bestellungen',       icon: '📦',
    keywords: ['bestellung','bestellbestätigung','order','versand','versandt','lieferung','geliefert','sendungsverfolgung','tracking','paket','shipped','shipping','ihre bestellung'] },
  { id: 'contracts', name: 'Verträge',           icon: '📄',
    keywords: ['vertrag','contract','kündigung','kuendigung','abo','abonnement','vertragsverlängerung','vertragsverlaengerung','agb','tarif','laufzeit','kündigungsfrist','kuendigungsfrist'] },
  { id: 'spam',      name: 'Spam',               icon: '🚫', system: true },
];
function suggestCategory({ subject = '', from = '' }) {
  const hay = `${subject} ${from}`.toLowerCase();
  for (const c of CATEGORIES) {
    if (c.keywords && c.keywords.some((k) => hay.includes(k))) return c.id;
  }
  return 'inbox';
}

// ---------------------------------------------------------------------------
// IMAP-Helfer
// ---------------------------------------------------------------------------
function clientFor(acc) {
  return new ImapFlow({
    host: acc.host,
    port: Number(acc.port) || 993,
    secure: acc.secure !== false,
    auth: { user: acc.user, pass: acc.pass },
    logger: false,
  });
}
async function fetchMailbox(client, mailboxPath, limit) {
  const out = [];
  const lock = await client.getMailboxLock(mailboxPath);
  try {
    const total = client.mailbox.exists;
    if (total > 0) {
      const start = Math.max(1, total - limit + 1);
      for await (const msg of client.fetch(`${start}:*`, { uid: true, envelope: true, flags: true })) {
        const env = msg.envelope || {};
        const f = (env.from && env.from[0]) || {};
        out.push({
          uid: msg.uid,
          seen: msg.flags ? msg.flags.has('\\Seen') : false,
          from: f.name ? `${f.name} <${f.address || ''}>` : (f.address || 'Unbekannt'),
          subject: env.subject || '(kein Betreff)',
          date: (env.date && env.date.toISOString) ? env.date.toISOString() : new Date().toISOString(),
        });
      }
    }
  } finally { lock.release(); }
  return out;
}
async function findJunkPath(client) {
  try {
    const list = await client.list();
    const junk = list.find((m) => m.specialUse === '\\Junk') || list.find((m) => /junk|spam/i.test(m.path));
    return junk ? junk.path : null;
  } catch { return null; }
}
async function inboxForAccount(acc, limit) {
  const client = clientFor(acc);
  try {
    await client.connect();
    const inbox = await fetchMailbox(client, 'INBOX', limit);
    let spam = [];
    const junk = await findJunkPath(client);
    if (junk) spam = await fetchMailbox(client, junk, Math.min(limit, 30));
    await client.logout();
    const tag = (arr, box) => arr.map((m) => ({
      ...m, box, suggested: box === 'spam' ? 'spam' : suggestCategory(m),
      accountId: acc.id, accountLabel: acc.label, accountEmail: acc.email || acc.user,
    }));
    return [...tag(inbox, 'inbox'), ...tag(spam, 'spam')];
  } catch (err) {
    try { await client.logout(); } catch {}
    throw err;
  }
}

// ---------------------------------------------------------------------------
// API (alles per POST, Zugangsdaten kommen aus dem Browser mit)
// ---------------------------------------------------------------------------
app.get('/api/categories', (req, res) => {
  res.json(CATEGORIES.map(({ keywords, ...c }) => c));
});

// Posteingang (ein oder mehrere Konten) – parallel, fehlertolerant.
// Der Browser schickt nur noch Konto-IDs, die Zugangsdaten liegen beim Benutzer.
app.post('/api/inbox', requireAuth, async (req, res) => {
  const all = userAccounts(req.user);
  const ids = Array.isArray(req.body?.accountIds) ? req.body.accountIds : null;
  const accounts = (ids ? all.filter((a) => ids.includes(a.id)) : all).map(accountFull);
  const limit = Math.min(Number(req.body?.limit) || 40, 100);
  if (!accounts.length) return res.json({ messages: [], errors: [] });

  const settled = await Promise.allSettled(accounts.map((a) => inboxForAccount(a, limit)));
  const messages = [];
  const errors = [];
  settled.forEach((r, i) => {
    if (r.status === 'fulfilled') messages.push(...r.value);
    else errors.push({ account: accounts[i].label || accounts[i].user, error: r.reason.message });
  });
  messages.sort((a, b) => new Date(b.date) - new Date(a.date));
  res.json({ messages, errors });
});

// einzelne Mail mit vollem Inhalt
app.post('/api/message', requireAuth, async (req, res) => {
  const { accountId, uid, spam } = req.body || {};
  const stored = userAccounts(req.user).find((a) => a.id === accountId);
  if (!stored || !uid) return res.status(400).json({ error: 'accountId und uid nötig.' });
  const client = clientFor(accountFull(stored));
  try {
    await client.connect();
    let mailboxPath = 'INBOX';
    if (spam) { const junk = await findJunkPath(client); if (junk) mailboxPath = junk; }
    const lock = await client.getMailboxLock(mailboxPath);
    try {
      const { content } = await client.download(Number(uid), undefined, { uid: true });
      const parsed = await simpleParser(content);
      res.json({
        uid,
        from: parsed.from?.text || 'Unbekannt',
        subject: parsed.subject || '(kein Betreff)',
        date: (parsed.date || new Date()).toISOString(),
        html: parsed.html || null,
        text: parsed.text || '',
      });
    } finally { lock.release(); }
    await client.logout();
  } catch (err) {
    try { await client.logout(); } catch {}
    res.status(502).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// PWA-Kram: Manifest + (Mini-)Service-Worker inline, damit alles in einer Datei bleibt
// ---------------------------------------------------------------------------
const ICON = 'data:image/svg+xml;base64,' + Buffer.from(
  "<svg xmlns='http://www.w3.org/2000/svg' width='512' height='512'><rect width='512' height='512' rx='96' fill='#13082b'/><rect x='112' y='168' width='288' height='176' rx='16' fill='#a855f7'/><path d='M120 180l136 104 136-104' fill='none' stroke='#13082b' stroke-width='22' stroke-linejoin='round'/></svg>"
).toString('base64');

app.get('/manifest.webmanifest', (req, res) => {
  res.type('application/manifest+json').json({
    name: 'Handy-Mail', short_name: 'Mail',
    start_url: '/', display: 'standalone', orientation: 'portrait',
    background_color: '#0b0416', theme_color: '#a855f7',
    icons: [
      { src: ICON, sizes: '192x192', type: 'image/svg+xml', purpose: 'any' },
      { src: ICON, sizes: '512x512', type: 'image/svg+xml', purpose: 'any maskable' },
    ],
  });
});
app.get('/sw.js', (req, res) => {
  res.type('application/javascript').send(
    "self.addEventListener('install',e=>self.skipWaiting());" +
    "self.addEventListener('activate',e=>self.clients.claim());" +
    "self.addEventListener('fetch',()=>{});"
  );
});

// Startseite
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`Handy-Mail (online) läuft auf Port ${PORT}`));
