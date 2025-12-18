# TempShare

TempShare is a lightweight, secure web application for temporary file sharing. Users upload a file and receive a single-use download link that automatically expires by time (e.g., 1 hour) or by download count (e.g., 1 or 3). Links are HMAC-signed to prevent forgery, and optional password protection is available. Recipients see clear file details (name/size and remaining time/downloads); if the rules are met and the password is correct, the download proceeds, otherwise the page clearly communicates expiry or exhaustion of limits.

To keep the service resilient, we emphasize self-healing: health checks (`/healthz`, `/readyz`), graceful shutdown, automatic restarts (Docker/PM2), and cleanup of expired records help the system recover without manual intervention. Abuse prevention is supported through rate limiting, explicit error messaging, and careful handling of secrets (no plaintext storage; passwords are only stored as bcrypt hashes).

## Scope
- Flow: upload → signed link → validated download
- Enforce time/download limits with optional password protection
- Secure coding: input validation, hashed passwords, security headers (CSP, Referrer-Policy, NoSniff)
- Light self-healing: health checks, graceful shutdown, auto-restart, expired-record cleanup
- Clear UI: upload page + single-file page with explicit status messages
- Abuse mitigation: rate limiting and basic audit logs (no sensitive data in logs)

## Technologies
- Frontend: HTML/CSS with minimal JavaScript
- Backend: Node.js + Express (uploads, signed tokens, downloads)
- Database: SQLite (single-file, zero-config)
- Security: HMAC-signed links, bcrypt for passwords, security headers (CSP, Referrer-Policy, NoSniff)
- Operations: Docker or PM2 for auto-restart; `/healthz` and `/readyz` for health checks

## Kurulum ve Çalıştırma

### Gereksinimler
- Node.js v18 veya üzeri (önerilen: v20+)
- npm (Node.js ile birlikte gelir)

### Adımlar

1. **Projeyi indirin ve açın**
   ```bash
   cd database
   ```

2. **Bağımlılıkları yükleyin**
   ```bash
   npm install
   ```
   
   **ÖNEMLİ:** Eğer `better-sqlite3` modülü ile ilgili hata alırsanız:
   ```bash
   # Windows PowerShell
   rmdir /s /q node_modules
   del package-lock.json
   npm install
   ```

3. **Sunucuyu başlatın**
   ```bash
   node index.js
   ```

4. **Tarayıcıda açın**
   - Ana sayfa: `http://localhost:3000`
   - İndirme sayfası: `http://localhost:3000/download.html?token=...`

### Sorun Giderme

**"NODE_MODULE_VERSION" hatası alıyorsanız:**
- Bu hata, `node_modules` klasörünün farklı bir Node.js sürümü ile derlenmiş olmasından kaynaklanır.
- **Çözüm:** `node_modules` klasörünü silip `npm install` çalıştırın (yukarıdaki adımlar).
- **Önleme:** Projeyi zip'lerken `node_modules` klasörünü dahil etmeyin. `.gitignore` dosyası zaten bunu engeller.

**Port 3000 zaten kullanılıyorsa:**
- `index.js` dosyasındaki `PORT` değişkenini değiştirin veya başka bir port kullanan servisi durdurun.