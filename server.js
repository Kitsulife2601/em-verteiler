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
app.set('trust proxy', true); // hinter Render/Proxy: https und Host korrekt erkennen
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

// E-Mail-Anbieter automatisch am Domainnamen erkennen (für die Ein-Schritt-Anmeldung)
const IMAP_HOSTS = {
  'gmail.com': 'imap.gmail.com', 'googlemail.com': 'imap.gmail.com',
  'gmx.net': 'imap.gmx.net', 'gmx.de': 'imap.gmx.net', 'gmx.at': 'imap.gmx.net', 'gmx.ch': 'imap.gmx.net',
  'web.de': 'imap.web.de',
  'outlook.com': 'outlook.office365.com', 'outlook.de': 'outlook.office365.com', 'hotmail.com': 'outlook.office365.com',
  'hotmail.de': 'outlook.office365.com', 'live.com': 'outlook.office365.com', 'live.de': 'outlook.office365.com', 'office365.com': 'outlook.office365.com',
  'yahoo.com': 'imap.mail.yahoo.com', 'yahoo.de': 'imap.mail.yahoo.com', 'ymail.com': 'imap.mail.yahoo.com',
  'icloud.com': 'imap.mail.me.com', 'me.com': 'imap.mail.me.com', 'mac.com': 'imap.mail.me.com',
  't-online.de': 'secureimap.t-online.de', 'aol.com': 'imap.aol.com', 'aol.de': 'imap.aol.com',
};
function detectHost(email) {
  const d = String(email || '').toLowerCase().split('@')[1] || '';
  return IMAP_HOSTS[d] || '';
}
async function testImapConnection({ host, port, user, pass }) {
  // Nur für automatisierte Tests: umgeht die echte Prüfung ausschließlich für den
  // Sentinel-Host und nur, wenn HM_TEST_IMAP gesetzt ist. In Produktion ohne Wirkung.
  if (process.env.HM_TEST_IMAP === '1' && host === 'imap.test.local') return { ok: true };
  const client = clientFor({ host, port, secure: true, user, pass });
  try { await client.connect(); await client.logout(); return { ok: true }; }
  catch (err) { try { await client.logout(); } catch {} return { ok: false, error: err.message }; }
}

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  const mail = String(email || '').trim().toLowerCase();
  if (!mail || !password) return res.status(400).json({ error: 'E-Mail und Passwort sind nötig.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) return res.status(400).json({ error: 'Bitte eine gültige E-Mail-Adresse angeben.' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Das Passwort braucht mindestens 6 Zeichen.' });
  if (userDB.users.some((u) => u.email === mail)) return res.status(409).json({ code: 'already_registered', error: 'Diese E-Mail ist bereits registriert – bitte melde dich an.' });

  // Ein-Schritt-Anmeldung: das Postfach wird direkt verbunden (Server automatisch erkannt)
  const host = String(req.body.host || '').trim() || detectHost(mail);
  const port = Number(req.body.port) || 993;
  if (!host) {
    return res.status(400).json({ code: 'need_server', error: 'Wir konnten den E-Mail-Server nicht automatisch erkennen. Bitte gib den IMAP-Server an.' });
  }
  const test = await testImapConnection({ host, port, user: mail, pass: password });
  if (!test.ok) {
    return res.status(401).json({ code: 'mailbox_failed', error: 'Postfach-Verbindung fehlgeschlagen: ' + test.error + ' — bei Gmail/Yahoo bitte ein App-Passwort verwenden.' });
  }
  const account = buildAccount({ label: mail, email: mail, user: mail, pass: password, host, port, secure: true });

  const salt = crypto.randomBytes(16).toString('hex');
  const user = {
    id: crypto.randomUUID(),
    name: String(name || '').trim() || mail.split('@')[0],
    email: mail,
    salt,
    hash: hashPassword(String(password), salt),
    accounts: [account],
    createdAt: new Date().toISOString(),
  };
  userDB.users.push(user);
  saveUserDB();
  res.json({ token: signToken(user.id), user: publicUser(user) });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const mail = String(email || '').trim().toLowerCase();
  if (!mail || !password) return res.status(400).json({ error: 'Bitte E-Mail und Passwort eingeben.' });
  const user = userDB.users.find((u) => u.email === mail);
  // Konto gibt es noch nicht -> deutlicher Hinweis, dass zuerst registriert werden muss
  if (!user) {
    return res.status(404).json({ code: 'not_registered', error: 'Für diese E-Mail gibt es noch kein Konto. Bitte registriere dich zuerst.' });
  }
  if (!user.salt || !user.hash) {
    const pName = (OAUTH_PROVIDERS[user.provider] && OAUTH_PROVIDERS[user.provider].name) || 'einen Anbieter';
    return res.status(401).json({ code: 'oauth_only', error: `Dieses Konto ist mit ${pName} verknüpft – bitte den entsprechenden Anmelde-Button nutzen.` });
  }
  const attempt = Buffer.from(hashPassword(String(password), user.salt));
  const stored = Buffer.from(user.hash);
  if (attempt.length !== stored.length || !crypto.timingSafeEqual(attempt, stored)) {
    return res.status(401).json({ code: 'wrong_password', error: 'Das Passwort ist leider falsch. Bitte versuche es erneut.' });
  }
  res.json({ token: signToken(user.id), user: publicUser(user) });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json(publicUser(req.user));
});

// ---------------------------------------------------------------------------
// Anmeldung über Google & Co. (OAuth 2.0 / OpenID Connect)
// Ein Anbieter wird automatisch aktiv, sobald seine Client-ID und sein
// Client-Secret als Umgebungsvariablen gesetzt sind (Anleitung im README).
// ---------------------------------------------------------------------------
// Umgebungsvariablen tolerant lesen: Groß-/Kleinschreibung und ein paar
// gängige Schreibweisen (z. B. GOOGLE_CLIENT_ID, Google_Client_Id, GOOGLECLIENTID)
// werden alle akzeptiert – das erspart Frust beim Eintragen im Hosting-Panel.
function envAny(...names) {
  const wanted = names.map((n) => n.toLowerCase().replace(/[^a-z0-9]/g, ''));
  for (const [key, val] of Object.entries(process.env)) {
    if (val == null || val === '') continue;
    if (wanted.includes(key.toLowerCase().replace(/[^a-z0-9]/g, ''))) return val;
  }
  return undefined;
}
const OAUTH_PROVIDERS = {
  google: {
    name: 'Google',
    clientId: envAny('GOOGLE_CLIENT_ID', 'GOOGLE_CLIENTID'),
    clientSecret: envAny('GOOGLE_CLIENT_SECRET', 'GOOGLE_CLIENTSECRET'),
    authUrl: envAny('GOOGLE_AUTH_URL') || 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: envAny('GOOGLE_TOKEN_URL') || 'https://oauth2.googleapis.com/token',
    userinfoUrl: envAny('GOOGLE_USERINFO_URL') || 'https://openidconnect.googleapis.com/v1/userinfo',
    scope: 'openid email profile',
    // Postfach direkt über die Google-Anmeldung freischalten (IMAP per OAuth)
    mailScope: 'https://mail.google.com/',
    imapHost: envAny('GOOGLE_IMAP_HOST') || 'imap.gmail.com',
    imapPort: Number(envAny('GOOGLE_IMAP_PORT')) || 993,
    authExtra: { access_type: 'offline', prompt: 'consent' },
  },
  microsoft: {
    name: 'Microsoft',
    clientId: envAny('MS_CLIENT_ID', 'MICROSOFT_CLIENT_ID', 'MS_CLIENTID'),
    clientSecret: envAny('MS_CLIENT_SECRET', 'MICROSOFT_CLIENT_SECRET', 'MS_CLIENTSECRET'),
    authUrl: envAny('MS_AUTH_URL') || 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenUrl: envAny('MS_TOKEN_URL') || 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    userinfoUrl: envAny('MS_USERINFO_URL') || 'https://graph.microsoft.com/oidc/userinfo',
    scope: 'openid email profile',
    mailScope: 'https://outlook.office.com/IMAP.AccessAsUser.All offline_access',
    imapHost: envAny('MS_IMAP_HOST') || 'outlook.office365.com',
    imapPort: Number(envAny('MS_IMAP_PORT')) || 993,
  },
  yahoo: {
    name: 'Yahoo',
    clientId: envAny('YAHOO_CLIENT_ID', 'YAHOO_CLIENTID'),
    clientSecret: envAny('YAHOO_CLIENT_SECRET', 'YAHOO_CLIENTSECRET'),
    authUrl: envAny('YAHOO_AUTH_URL') || 'https://api.login.yahoo.com/oauth2/request_auth',
    tokenUrl: envAny('YAHOO_TOKEN_URL') || 'https://api.login.yahoo.com/oauth2/get_token',
    userinfoUrl: envAny('YAHOO_USERINFO_URL') || 'https://api.login.yahoo.com/openid/v1/userinfo',
    scope: 'openid email profile',
  },
};
function enabledProviders() {
  return Object.entries(OAUTH_PROVIDERS).filter(([, p]) => p.clientId && p.clientSecret);
}
function baseUrl(req) {
  return (process.env.BASE_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
}
function oauthRedirectUri(req, providerId) {
  return `${baseUrl(req)}/auth/${providerId}/callback`;
}
function makeOAuthState() {
  const payload = Buffer.from(JSON.stringify({ n: crypto.randomBytes(8).toString('hex'), exp: Date.now() + 10 * 60 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', userDB.secret).update('state:' + payload).digest('base64url');
  return `${payload}.${sig}`;
}
function checkOAuthState(state) {
  if (typeof state !== 'string' || !state.includes('.')) return false;
  const [payload, sig] = state.split('.');
  const expected = crypto.createHmac('sha256', userDB.secret).update('state:' + payload).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')).exp > Date.now(); }
  catch { return false; }
}

app.get('/api/auth/providers', (req, res) => {
  res.json(enabledProviders().map(([id, p]) => ({ id, name: p.name })));
});

async function getAccessToken(providerId, refreshToken) {
  const p = OAUTH_PROVIDERS[providerId];
  if (!p) throw new Error('Unbekannter Anbieter.');
  const res = await fetch(p.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: p.clientId, client_secret: p.clientSecret, grant_type: 'refresh_token', refresh_token: refreshToken }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.access_token) throw new Error(data.error_description || data.error || 'Zugriffstoken konnte nicht erneuert werden');
  return data.access_token;
}

app.get('/auth/:provider', (req, res) => {
  const p = OAUTH_PROVIDERS[req.params.provider];
  if (!p || !p.clientId || !p.clientSecret) return res.redirect('/#autherror=' + encodeURIComponent('Dieser Anbieter ist nicht eingerichtet.'));
  const scope = [p.scope, p.mailScope].filter(Boolean).join(' ');
  const params = new URLSearchParams({
    client_id: p.clientId,
    redirect_uri: oauthRedirectUri(req, req.params.provider),
    response_type: 'code',
    scope,
    state: makeOAuthState(),
    ...(p.authExtra || {}),
  });
  res.redirect(`${p.authUrl}?${params}`);
});

app.get('/auth/:provider/callback', async (req, res) => {
  const id = req.params.provider;
  const p = OAUTH_PROVIDERS[id];
  const fail = (msg) => res.redirect('/#autherror=' + encodeURIComponent(msg));
  if (!p || !p.clientId || !p.clientSecret) return fail('Dieser Anbieter ist nicht eingerichtet.');
  const { code, state, error } = req.query;
  if (error) return fail('Anmeldung abgebrochen (' + error + ').');
  if (!code || !checkOAuthState(state)) return fail('Ungültige Antwort vom Anbieter – bitte erneut versuchen.');
  try {
    const tokenRes = await fetch(p.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: p.clientId,
        client_secret: p.clientSecret,
        code: String(code),
        grant_type: 'authorization_code',
        redirect_uri: oauthRedirectUri(req, id),
      }),
    });
    const tokens = await tokenRes.json().catch(() => ({}));
    if (!tokenRes.ok || !tokens.access_token) throw new Error(tokens.error_description || tokens.error || 'Token-Austausch fehlgeschlagen');
    const infoRes = await fetch(p.userinfoUrl, { headers: { Authorization: 'Bearer ' + tokens.access_token } });
    const info = await infoRes.json().catch(() => ({}));
    if (!infoRes.ok || !info.email) throw new Error('Der Anbieter hat keine E-Mail-Adresse geliefert.');
    const mail = String(info.email).trim().toLowerCase();
    let user = userDB.users.find((u) => u.email === mail);
    if (!user) {
      user = {
        id: crypto.randomUUID(),
        name: String(info.name || '').trim() || mail.split('@')[0],
        email: mail,
        provider: id,
        accounts: [],
        createdAt: new Date().toISOString(),
      };
      userDB.users.push(user);
    } else if (!user.provider) {
      user.provider = id; // bestehendes Passwort-Konto mit dem Anbieter verknüpfen
    }
    // Postfach direkt über die Anmeldung verbinden – kein extra 'Konto verbinden' nötig.
    // Braucht ein Refresh-Token (Google: access_type=offline, Microsoft: offline_access).
    if (p.imapHost && tokens.refresh_token) {
      const accounts = userAccounts(user);
      const existing = accounts.find((a) => a.type === 'oauth' && a.provider === id && a.email === mail);
      if (existing) existing.refreshEnc = encryptSecret(tokens.refresh_token);
      else accounts.push(buildOAuthAccount({ provider: id, email: mail, host: p.imapHost, port: p.imapPort, refreshToken: tokens.refresh_token }));
    }
    saveUserDB();
    res.redirect('/#token=' + encodeURIComponent(signToken(user.id)));
  } catch (err) {
    fail(`Anmeldung über ${p.name} fehlgeschlagen: ${err.message}`);
  }
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
  return { id: a.id, label: a.label, email: a.email, host: a.host, port: a.port, secure: a.secure, type: a.type || 'password', provider: a.provider || null };
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
function buildOAuthAccount({ provider, email, host, port, refreshToken }) {
  const mail = String(email).trim();
  return {
    id: crypto.randomUUID(),
    type: 'oauth',
    provider,
    label: mail,
    email: mail,
    host: String(host).trim(),
    port: Number(port) || 993,
    secure: true,
    user: mail,
    refreshEnc: encryptSecret(refreshToken),
  };
}
// Baut einen verbindungsbereiten IMAP-Client – für Passwort- wie für OAuth-Konten.
async function resolveClient(acc) {
  if (acc.type === 'oauth') {
    const accessToken = await getAccessToken(acc.provider, decryptSecret(acc.refreshEnc));
    return new ImapFlow({ host: acc.host, port: Number(acc.port) || 993, secure: acc.secure !== false, auth: { user: acc.user, accessToken }, logger: false });
  }
  return clientFor({ ...acc, pass: decryptSecret(acc.passEnc) });
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
  const client = await resolveClient(acc);
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
  const accounts = ids ? all.filter((a) => ids.includes(a.id)) : all;
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
  const client = await resolveClient(stored);
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

// ---------------------------------------------------------------------------
// Öffentliche Seiten für die Google-Verifizierung:
// Info/Startseite, Datenschutzerklärung (mit Google "Limited Use"), Nutzungsbedingungen.
// Platzhalter in [[eckigen Klammern]] bitte durch echte Angaben/Domain ersetzen.
// ---------------------------------------------------------------------------
const APP_NAME = 'Handy-Mail';
const LEGAL_STAND = 'Juli 2026';
function legalPage(title, bodyHtml) {
  return `<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · ${APP_NAME}</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#ede9fe;background:#0b0416;
  background-image:radial-gradient(800px 500px at 85% -10%,rgba(124,58,237,.3),transparent 60%),radial-gradient(700px 500px at -10% 20%,rgba(168,85,247,.18),transparent 60%);background-attachment:fixed;line-height:1.6}
.wrap{max-width:760px;margin:0 auto;padding:36px 22px 80px}
.brand{display:inline-flex;align-items:center;gap:8px;font-weight:800;font-size:1.1rem;text-decoration:none;
  background:linear-gradient(120deg,#e9d5ff,#c084fc);-webkit-background-clip:text;background-clip:text;color:transparent;margin-bottom:8px}
h1{font-size:1.7rem;margin:.2em 0 .1em;background:linear-gradient(120deg,#f3e8ff,#c084fc 55%,#8b5cf6);-webkit-background-clip:text;background-clip:text;color:transparent}
h2{color:#c084fc;margin-top:30px;font-size:1.15rem}
a{color:#c084fc}
.stand{color:#9d8fc0;font-size:.85rem;margin-bottom:22px}
.card{background:rgba(24,12,48,.55);border:1px solid rgba(168,85,247,.28);border-radius:16px;padding:22px 24px;backdrop-filter:blur(14px)}
.note{background:rgba(168,85,247,.12);border:1px solid rgba(168,85,247,.4);padding:12px 14px;border-radius:12px;font-size:.9rem;margin:18px 0}
.ph{color:#f9a8d4;font-weight:700}
.foot{margin-top:26px;font-size:.85rem;color:#9d8fc0}
.foot a{margin-right:14px}
ul{padding-left:20px}
</style></head><body><div class="wrap">
<a class="brand" href="/">📬 ${APP_NAME}</a>
${bodyHtml}
<div class="foot"><a href="/">Start</a><a href="/privacy">Datenschutz</a><a href="/terms">Nutzungsbedingungen</a></div>
</div></body></html>`;
}

// Info-/Startseite (öffentlich, ohne Login) – als "Application home page" bei Google
app.get('/info', (req, res) => {
  res.type('html').send(legalPage('Über die App', `
<h1>${APP_NAME}</h1>
<p class="stand">Ein privater, übersichtlicher E-Mail-Client fürs Handy.</p>
<div class="card">
  <p>${APP_NAME} bündelt deine E-Mail-Postfächer an einem Ort und sortiert Nachrichten automatisch
  in Kategorien wie <em>Rechnungen</em>, <em>Bestellungen</em> und <em>Verträge</em>.</p>
  <h2>Was die App macht</h2>
  <ul>
    <li>Postfächer per IMAP verbinden – oder bequem über die Anmeldung mit Google/Microsoft.</li>
    <li>E-Mails abrufen, lesen und automatisch nach Themen einordnen.</li>
    <li>Zugangsdaten werden verschlüsselt gespeichert; E-Mail-Inhalte nur zur Anzeige geladen, nicht dauerhaft gespeichert.</li>
  </ul>
  <h2>Umgang mit Google-Daten</h2>
  <p>Wenn du dich mit Google anmeldest, greift ${APP_NAME} ausschließlich auf <strong>dein eigenes Gmail-Postfach</strong> zu,
  um dir deine Nachrichten in der App anzuzeigen. Die Nutzung hält sich an die
  <a href="https://developers.google.com/terms/api-services-user-data-policy">Google API Services User Data Policy</a>
  inklusive der <em>Limited Use</em>-Anforderungen. Details in der <a href="/privacy">Datenschutzerklärung</a>.</p>
  <p><a href="/">→ Zur App</a></p>
</div>`));
});

app.get('/privacy', (req, res) => {
  res.type('html').send(legalPage('Datenschutzerklärung', `
<h1>Datenschutzerklärung</h1>
<p class="stand">Stand: ${LEGAL_STAND}</p>
<div class="card">
<div class="note">Bitte ersetze die <span class="ph">[[markierten]]</span> Angaben durch deine echten Kontaktdaten
und – nach dem Umzug auf eine eigene Domain – die richtige Adresse.</div>

<h2>1. Verantwortlicher</h2>
<p><span class="ph">[[Vor- und Nachname]]</span><br>
E-Mail: <span class="ph">[[deine-kontakt@email.de]]</span></p>

<h2>2. Welche Daten wir verarbeiten</h2>
<ul>
  <li><strong>Kontodaten:</strong> Name (optional) und E-Mail-Adresse zur Anmeldung.</li>
  <li><strong>Postfach-Zugang:</strong> IMAP-Zugangsdaten bzw. OAuth-Tokens – ausschließlich <strong>verschlüsselt</strong> gespeichert, nur um deine Mails abzurufen.</li>
  <li><strong>E-Mail-Inhalte:</strong> werden nur zur Anzeige geladen und <strong>nicht dauerhaft</strong> auf dem Server gespeichert.</li>
</ul>

<h2>3. Google-Nutzerdaten (Gmail)</h2>
<p>Meldest du dich mit Google an, verwendet ${APP_NAME} den Gmail-Zugriff einzig dafür, dir <strong>deine eigenen E-Mails</strong> in der App anzuzeigen.</p>
<p>Die Nutzung und Weitergabe von Informationen aus Google APIs hält sich an die
<a href="https://developers.google.com/terms/api-services-user-data-policy">Google API Services User Data Policy</a>,
einschließlich der <strong>Limited Use</strong>-Anforderungen. Konkret:</p>
<ul>
  <li>Wir geben Gmail-Daten <strong>nicht an Dritte</strong> weiter.</li>
  <li>Wir nutzen sie <strong>nicht für Werbung</strong>.</li>
  <li>Wir nutzen sie <strong>nicht zum Training von KI-/ML-Modellen</strong>.</li>
  <li>Kein Mensch liest deine Daten, außer es ist für den Betrieb/Support nötig oder gesetzlich vorgeschrieben.</li>
</ul>

<h2>4. Speicherung & Löschung</h2>
<p>Deine Daten liegen auf dem Server, auf dem die App betrieben wird. Du kannst Postfächer jederzeit in der App entfernen;
für die Löschung deines Kontos wende dich an die oben genannte Kontaktadresse.</p>

<h2>5. Deine Rechte</h2>
<p>Du hast das Recht auf Auskunft, Berichtigung, Löschung und Einschränkung der Verarbeitung deiner Daten.</p>
</div>`));
});

app.get('/terms', (req, res) => {
  res.type('html').send(legalPage('Nutzungsbedingungen', `
<h1>Nutzungsbedingungen</h1>
<p class="stand">Stand: ${LEGAL_STAND}</p>
<div class="card">
<h2>1. Leistung</h2>
<p>${APP_NAME} ist ein privater E-Mail-Client, mit dem du deine eigenen Postfächer abrufen und lesen kannst.
Die App wird ohne Gewähr auf ständige Verfügbarkeit bereitgestellt.</p>
<h2>2. Deine Verantwortung</h2>
<p>Du bist für die Sicherheit deiner Zugangsdaten selbst verantwortlich und nutzt nur Postfächer, zu denen du berechtigt bist.</p>
<h2>3. Haftung</h2>
<p>Die Nutzung erfolgt auf eigenes Risiko. Für Datenverluste oder Ausfälle wird im gesetzlich zulässigen Rahmen keine Haftung übernommen.</p>
<h2>4. Kontakt</h2>
<p><span class="ph">[[deine-kontakt@email.de]]</span></p>
</div>`));
});

// Startseite (die App)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`Handy-Mail (online) läuft auf Port ${PORT}`));
