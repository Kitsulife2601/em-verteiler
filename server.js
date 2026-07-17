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

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8080;

const app = express();
app.use(express.json({ limit: '1mb' }));

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

// Verbindung testen (beim Konto-Hinzufügen)
app.post('/api/test', async (req, res) => {
  const { host, port, secure, user, pass } = req.body || {};
  if (!host || !user || !pass) return res.status(400).json({ error: 'Host, Benutzer und Passwort nötig.' });
  const client = clientFor({ host, port, secure, user, pass });
  try {
    await client.connect();
    await client.logout();
    res.json({ ok: true });
  } catch (err) {
    res.status(401).json({ error: 'Anmeldung fehlgeschlagen: ' + err.message });
  }
});

// Posteingang (ein oder mehrere Konten) – parallel, fehlertolerant
app.post('/api/inbox', async (req, res) => {
  const accounts = Array.isArray(req.body?.accounts) ? req.body.accounts : [];
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
app.post('/api/message', async (req, res) => {
  const { account, uid, spam } = req.body || {};
  if (!account || !uid) return res.status(400).json({ error: 'account und uid nötig.' });
  const client = clientFor(account);
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
const ICON = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIHdpZHRoPSc1MTInIGhlaWdodD0nNTEyJz48cmVjdCB3aWR0aD0nNTEyJyBoZWlnaHQ9JzUxMicgcng9Jzk2JyBmaWxsPScjMWY2ZmViJy8+PHJlY3QgeD0nMTEyJyB5PScxNjgnIHdpZHRoPScyODgnIGhlaWdodD0nMTc2JyByeD0nMTYnIGZpbGw9J3doaXRlJy8+PHBhdGggZD0nTTEyMCAxODBsMTM2IDEwNCAxMzYtMTA0JyBmaWxsPSdub25lJyBzdHJva2U9JyMxZjZmZWInIHN0cm9rZS13aWR0aD0nMjInIHN0cm9rZS1saW5lam9pbj0ncm91bmQnLz48L3N2Zz4=';

app.get('/manifest.webmanifest', (req, res) => {
  res.type('application/manifest+json').json({
    name: 'Handy-Mail', short_name: 'Mail',
    start_url: '/', display: 'standalone', orientation: 'portrait',
    background_color: '#f5f6f8', theme_color: '#1f6feb',
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
