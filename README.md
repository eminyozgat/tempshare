# TempShare

TempShare, geçici dosya paylaşımı için geliştirilmiş hafif ve güvenli bir web uygulamasıdır. Dosya yükleyip, zaman (örn. 1 saat) veya indirme sayısı (örn. 1 veya 3) ile otomatik olarak sona eren tek kullanımlık bir indirme bağlantısı alırsınız. Bağlantılar sahteciliği önlemek için HMAC ile imzalanır ve isteğe bağlı şifre koruması mevcuttur. Alıcılar dosya detaylarını (isim/boyut ve kalan süre/indirme hakkı) görür; kurallar sağlanırsa ve şifre doğruysa indirme başlar, aksi halde sayfa süre dolması veya limit aşımını açıkça bildirir.

Servisin güvenilir kalması için self-healing özellikler ekledik: health check'ler (`/healthz`, `/readyz`), graceful shutdown, otomatik yeniden başlatma (Docker/PM2) ve süresi dolmuş kayıtların temizlenmesi sistemin manuel müdahale olmadan kendini toparlamasına yardımcı olur. Kötüye kullanımı önlemek için rate limiting, net hata mesajları ve hassas bilgilerin dikkatli işlenmesi (düz metin saklama yok; şifreler sadece bcrypt hash'leri olarak saklanır) kullanılır.

## Özellikler
- Dosya yükleme → imzalı bağlantı → doğrulanmış indirme akışı
- Zaman/indirme limitleri ve isteğe bağlı şifre koruması
- Güvenli kodlama: input validation, hash'lenmiş şifreler, güvenlik başlıkları (CSP, Referrer-Policy, NoSniff)
- Self-healing: health check'ler, graceful shutdown, otomatik yeniden başlatma, süresi dolmuş kayıt temizliği
- Sade arayüz: yükleme sayfası + tek dosya sayfası net durum mesajlarıyla
- Kötüye kullanım önleme: rate limiting ve temel audit log'ları (hassas veri log'lanmaz)

<<<<<<< HEAD
## Teknolojiler
- **Frontend:** HTML/CSS ve minimal JavaScript
- **Backend:** Node.js + Express (yükleme, imzalı token'lar, indirme)
- **Veritabanı:** SQLite (tek dosya, sıfır yapılandırma)
- **Güvenlik:** HMAC-imzalı bağlantılar, bcrypt ile şifre hash'leme, güvenlik başlıkları
- **Operasyonlar:** Docker veya PM2 ile otomatik yeniden başlatma; `/healthz` ve `/readyz` health check'leri
=======
## Technologies
- Frontend: HTML/CSS with minimal JavaScript
- Backend: Node.js + Express (uploads, signed tokens, downloads)
- Database: SQLite (single-file, zero-config)
- Security: HMAC-signed links, bcrypt for passwords, security headers (CSP, Referrer-Policy, NoSniff)
- Operations: Docker or PM2 for auto-restart; `/healthz` and `/readyz` for health checks
>>>>>>> fdcaf2147072bdca40fc1365a6259795548e763f

## Kurulum ve Çalıştırma

### Gereksinimler
- Node.js v18 veya üzeri (önerilen: v20+)
- npm (Node.js ile birlikte gelir)

<<<<<<< HEAD
### Hızlı Başlangıç

1. **Projeyi klonlayın veya indirin**
=======
### Adımlar

1. **Projeyi indirin ve açın**
>>>>>>> fdcaf2147072bdca40fc1365a6259795548e763f
   ```bash
   cd database
   ```

2. **Bağımlılıkları yükleyin**
   ```bash
   npm install
   ```
   
<<<<<<< HEAD
   > **Not:** `better-sqlite3` native modül olduğu için farklı Node.js sürümlerinde sorun çıkabilir. Hata alırsanız `node_modules` ve `package-lock.json` dosyalarını silip tekrar `npm install` çalıştırın.
=======
   **ÖNEMLİ:** Eğer `better-sqlite3` modülü ile ilgili hata alırsanız:
   ```bash
   # Windows PowerShell
   rmdir /s /q node_modules
   del package-lock.json
   npm install
   ```
>>>>>>> fdcaf2147072bdca40fc1365a6259795548e763f

3. **Sunucuyu başlatın**
   ```bash
   node index.js
   ```

4. **Tarayıcıda açın**
   - Ana sayfa: `http://localhost:3000`
   - İndirme sayfası: `http://localhost:3000/download.html?token=...`

### Sorun Giderme

<<<<<<< HEAD
**"NODE_MODULE_VERSION" hatası:**
- `node_modules` klasörünü silin ve `npm install` çalıştırın
- Projeyi paylaşırken `node_modules` klasörünü dahil etmeyin

**Port 3000 kullanımda:**
- `PORT` environment variable'ını değiştirin veya başka bir port kullanan servisi durdurun
=======
**"NODE_MODULE_VERSION" hatası alıyorsanız:**
- Bu hata, `node_modules` klasörünün farklı bir Node.js sürümü ile derlenmiş olmasından kaynaklanır.
- **Çözüm:** `node_modules` klasörünü silip `npm install` çalıştırın (yukarıdaki adımlar).
- **Önleme:** Projeyi zip'lerken `node_modules` klasörünü dahil etmeyin. `.gitignore` dosyası zaten bunu engeller.

**Port 3000 zaten kullanılıyorsa:**
- `index.js` dosyasındaki `PORT` değişkenini değiştirin veya başka bir port kullanan servisi durdurun.
>>>>>>> fdcaf2147072bdca40fc1365a6259795548e763f
