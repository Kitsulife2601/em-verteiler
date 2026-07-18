# Handy-Mail (em-verteiler)

Mail-App mit eigener Anmeldung (E-Mail + Passwort oder Google/Microsoft/Yahoo),
Neon-Lila-Design und IMAP-Postfächern, die pro Benutzer auf dem Server gespeichert werden.

## Starten

```bash
npm install
npm start        # läuft auf Port 8080 (bzw. PORT aus der Umgebung)
```

## Anmeldung über Google & Co. einrichten

Die Buttons „Weiter mit Google/Microsoft/Yahoo" erscheinen **automatisch**, sobald die
passenden Umgebungsvariablen gesetzt sind. Ohne diese Variablen funktioniert die App
ganz normal mit E-Mail + Passwort.

### Google (empfohlen)

Die Google-Anmeldung schaltet gleich das **Gmail-Postfach** frei (per IMAP über OAuth),
sodass kein separates Postfach mehr verbunden werden muss. Dafür wird die Berechtigung
`https://mail.google.com/` angefragt.

1. Öffne die [Google Cloud Console](https://console.cloud.google.com/) und lege ein Projekt an (kostenlos).
2. Gehe zu **APIs & Dienste → OAuth-Zustimmungsbildschirm**: Typ „Extern" wählen,
   App-Name und deine E-Mail eintragen. Unter „Testnutzer" deine eigene Google-Adresse
   hinzufügen (solange die App im Testmodus ist).
   - Unter **Bereiche/Scopes** (bzw. „Scopes hinzufügen") den Bereich
     `https://mail.google.com/` hinzufügen. Das ist ein „sensibler/eingeschränkter"
     Bereich: Solange die App im **Testmodus** ist und du **Testnutzer** bist, funktioniert
     er sofort – Google zeigt beim Anmelden nur einen Warnhinweis („Google hat diese App
     nicht bestätigt"), den du über **Erweitert → Weiter zu … (unsicher)** bestätigst.
     Für die Nutzung durch fremde Personen müsste die App später von Google verifiziert werden.
3. Gehe zu **APIs & Dienste → Anmeldedaten → Anmeldedaten erstellen → OAuth-Client-ID**:
   - Anwendungstyp: **Webanwendung**
   - Autorisierte Weiterleitungs-URI: `https://DEINE-APP.onrender.com/auth/google/callback`
     (ersetze `DEINE-APP.onrender.com` durch deine echte Render-Adresse)
4. Kopiere **Client-ID** und **Client-Secret**.
5. In Render: Service öffnen → **Environment** → zwei Variablen anlegen:
   - `GOOGLE_CLIENT_ID` = deine Client-ID
   - `GOOGLE_CLIENT_SECRET` = dein Client-Secret
6. Speichern – Render startet neu, danach erscheint „Weiter mit Google" auf der Anmeldeseite.

> Hinweis: Wenn du den Gmail-Bereich neu hinzufügst, beim nächsten Login unbedingt die
> Zustimmung erneut erteilen (die App fragt mit `prompt=consent` nach), damit Google ein
> Refresh-Token ausstellt – nur dann kann das Postfach dauerhaft abgerufen werden.

### Microsoft (Outlook / Office365)

1. [Azure-Portal](https://portal.azure.com/) → **Microsoft Entra ID → App-Registrierungen → Neue Registrierung**
2. Unterstützte Kontotypen: „Konten in einem beliebigen Organisationsverzeichnis und persönliche Microsoft-Konten"
3. Umleitungs-URI (Web): `https://DEINE-APP.onrender.com/auth/microsoft/callback`
4. Unter **API-Berechtigungen** die Berechtigungen `offline_access` und
   `IMAP.AccessAsUser.All` (Office 365 Exchange Online) hinzufügen – damit wird das
   Outlook-Postfach wie bei Google automatisch verbunden.
5. Unter **Zertifikate & Geheimnisse** ein Client-Secret erstellen.
6. Render-Umgebungsvariablen: `MS_CLIENT_ID` und `MS_CLIENT_SECRET`

### Yahoo

1. [Yahoo Developer](https://developer.yahoo.com/apps/) → App erstellen, OpenID Connect aktivieren
2. Redirect-URI: `https://DEINE-APP.onrender.com/auth/yahoo/callback`
3. Render-Umgebungsvariablen: `YAHOO_CLIENT_ID` und `YAHOO_CLIENT_SECRET`

### Weitere Variablen (optional)

| Variable   | Bedeutung                                                                 |
|------------|---------------------------------------------------------------------------|
| `BASE_URL` | Öffentliche Adresse der App, z. B. `https://deine-app.onrender.com`. Nur nötig, falls die automatische Erkennung hinter dem Proxy nicht greift. |
| `DATA_DIR` | Verzeichnis für `users.json` (Benutzer + verschlüsselte IMAP-Konten). Auf Render am besten auf eine [Persistent Disk](https://render.com/docs/disks) zeigen lassen, sonst gehen Konten bei jedem Neustart verloren. |

## Wichtig für Render

- `users.json` liegt im Dateisystem. Ohne Persistent Disk ist die Datei nach jedem
  Deploy/Neustart leer – Benutzer müssten sich neu registrieren. Mit Google-Login ist das
  halb so schlimm (einfach wieder „Weiter mit Google"), IMAP-Konten müssten aber neu
  angelegt werden. Für dauerhaften Betrieb: Persistent Disk mounten und `DATA_DIR` darauf zeigen.
