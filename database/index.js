const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

// Veritabanı yöneticileri
const userManager = require('./src/database/userManager');
const fileManager = require('./src/database/fileManager');
const reportManager = require('./src/database/reportManager');

const app = express();

// Railway gibi proxy arkasında çalışırken gerçek IP'yi almak için
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

// HMAC şifreleme için gizli anahtar (production'da environment variable kullanılmalı)
const HMAC_SECRET = process.env.HMAC_SECRET || 'temp-share-secret-key-change-in-production';

// Token oluştur (HMAC ile imzalanmış)
const createSignedToken = (fileId, expiresAt) => {
    const payload = `${fileId}:${expiresAt}`;
    const signature = crypto.createHmac('sha256', HMAC_SECRET)
        .update(payload)
        .digest('hex');
    const token = Buffer.from(payload).toString('base64url');
    return `${token}.${signature}`;
};

// Token doğrula (HMAC imzasını kontrol et)
const verifySignedToken = (signedToken) => {
    try {
        const [token, signature] = signedToken.split('.');
        if (!token || !signature) return null;
        
        const payload = Buffer.from(token, 'base64url').toString('utf-8');
        const [fileId, expiresAt] = payload.split(':');
        
        const expectedSignature = crypto.createHmac('sha256', HMAC_SECRET)
            .update(payload)
            .digest('hex');
        
        if (signature !== expectedSignature) return null;
        
        return { fileId, expiresAt: parseInt(expiresAt) };
    } catch (e) {
        return null;
    }
};

// --- GİRDİ DOĞRULAMA FONKSİYONLARI ---

// E-posta formatı kontrolü
const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 255;
};

// String temizleme (XSS saldırılarına karşı koruma)
const sanitizeString = (str, maxLength = 1000) => {
    if (typeof str !== 'string') return '';
    return str
        .trim()
        .substring(0, maxLength)
        .replace(/[<>]/g, ''); // HTML karakterlerini temizle
};

// İsim doğrulama (harf, rakam, boşluk ve Türkçe karakterler)
const isValidName = (name) => {
    if (!name || typeof name !== 'string') return false;
    const trimmed = name.trim();
    if (trimmed.length < 2 || trimmed.length > 100) return false;
    // Sadece harf, rakam, boşluk ve bazı özel karakterlere izin ver
    const nameRegex = /^[a-zA-ZğüşıöçĞÜŞİÖÇ\s\-'\.]+$/;
    return nameRegex.test(trimmed);
};

// Şifre doğrulama
const isValidPassword = (password) => {
    if (!password || typeof password !== 'string') return false;
    return password.length >= 6 && password.length <= 128;
};

// Middleware ayarları

// CORS: production'da sadece belirli bir origin'e izin ver
const allowedOrigin = process.env.ALLOWED_ORIGIN;
if (allowedOrigin) {
    app.use(cors({ origin: allowedOrigin }));
} else {
    app.use(cors());
}

// Güvenlik başlıkları
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"], // CSS için inline kod gerekli
            scriptSrc: ["'self'", "'unsafe-inline'"], // JavaScript için inline kod gerekli
            imgSrc: ["'self'", "data:", "https://api.qrserver.com"], // QR kod servisi için
            connectSrc: ["'self'"]
        }
    },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    noSniff: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting - kötüye kullanımı önlemek için
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika içinde
    max: 20, // maksimum 20 istek
    standardHeaders: true,
    legacyHeaders: false
});

const downloadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 saat içinde
    max: 100, // maksimum 100 istek
    standardHeaders: true,
    legacyHeaders: false
});

app.use('/api/auth/', authLimiter);
app.use('/api/files/', downloadLimiter);

// Frontend dosyaları (HTML, CSS, JS)
// Railway'de ve local'de farklı yollar kullanılıyor, otomatik tespit ediliyor
const publicDir = fs.existsSync(path.join(__dirname, './public')) 
    ? path.join(__dirname, './public') 
    : path.join(__dirname, '../public');
app.use(express.static(publicDir));

// Yüklenen dosyaların saklanacağı klasör
// Railway'de tek volume kullanıyoruz: /app/storage
// Local'de proje klasörü içinde uploads/ klasörü
const storageBase = process.env.STORAGE_BASE || path.join(__dirname, '../');
const uploadDir = path.join(storageBase, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer yapılandırması (dosya yükleme için)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // Her dosyaya benzersiz bir isim ver (çakışmaları önlemek için)
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname);
    }
});

// Dosya yükleme ayarları
// Maksimum dosya boyutu: 100MB
// Tüm dosya türleri kabul edilir (sadece boyut kontrolü var)
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 100 * 1024 * 1024 // 100MB
    }
});

// --- API ROUTE'LARI ---

// 1. Kullanıcı Kaydı
app.post('/api/auth/register', async (req, res) => {
    try {
        let { name, email, password } = req.body;
        
        // Girdi kontrolü
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Tüm alanlar zorunludur.' });
        }
        
        // Girdileri temizle
        name = sanitizeString(name, 100);
        email = email.trim().toLowerCase();
        password = password.trim();
        
        // İsim kontrolü
        if (!isValidName(name)) {
            return res.status(400).json({ error: 'Geçersiz isim. İsim 2-100 karakter arasında olmalı ve sadece harf, boşluk ve bazı özel karakterler içermelidir.' });
        }
        
        // E-posta kontrolü
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: 'Geçersiz e-posta adresi.' });
        }
        
        // Şifre kontrolü
        if (!isValidPassword(password)) {
            return res.status(400).json({ error: 'Şifre 6-128 karakter arasında olmalıdır.' });
        }

        const existingUser = userManager.getUserByEmail(email);
        if (existingUser) {
            return res.status(400).json({ error: 'Bu e-posta adresi zaten kayıtlı.' });
        }

        const id = uuidv4();
        await userManager.createUser({ id, name, email, password });
        
        // Kayıt sonrası otomatik giriş
        const user = userManager.getUserById(id);
        console.log(`[REGISTER] Yeni üye kaydı: ${email}`);
        res.status(201).json({ message: 'Kayıt başarılı.', user: { id: user.id, name: user.name, email: user.email } });
    } catch (error) {
        res.status(500).json({ error: 'Kayıt sırasında bir hata oluştu.' });
    }
});

// 2. Kullanıcı Girişi
app.post('/api/auth/login', async (req, res) => {
    try {
        let { email, password } = req.body;
        
        // Girdi kontrolü
        if (!email || !password) {
            return res.status(400).json({ error: 'E-posta ve şifre zorunludur.' });
        }
        
        // Girdileri temizle
        email = email.trim().toLowerCase();
        password = password.trim();
        
        // E-posta formatı kontrolü
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: 'Geçersiz e-posta adresi.' });
        }
        
        // Şifre kontrolü
        if (!isValidPassword(password)) {
            return res.status(400).json({ error: 'Geçersiz şifre.' });
        }
        
        const user = userManager.getUserByEmail(email);

        if (!user) {
            return res.status(401).json({ error: 'E-posta veya şifre hatalı.' });
        }

        const isValid = await userManager.verifyPassword(user, password);
        if (!isValid) {
            return res.status(401).json({ error: 'E-posta veya şifre hatalı.' });
        }

        userManager.touchLastLogin(user.id);
        console.log(`[LOGIN] Kullanıcı girişi: ${email}`);
        res.json({ message: 'Giriş başarılı.', user: { id: user.id, name: user.name, email: user.email } });
    } catch (error) {
        res.status(500).json({ error: 'Giriş sırasında bir hata oluştu.' });
    }
});

// 3. Dosya Yükleme
const uploadMiddleware = upload.array('file[]');

app.post('/api/upload', (req, res) => {
    uploadMiddleware(req, res, async (err) => {
        // Dosya yükleme hatalarını kontrol et
        if (err) {
            if (err instanceof multer.MulterError) {
                if (err.code === 'LIMIT_FILE_SIZE') {
                    return res.status(400).json({ error: 'Dosya boyutu çok büyük. Maksimum 100MB.' });
                }
                return res.status(400).json({ error: 'Dosya yükleme hatası (Multer).' });
            }
            return res.status(500).json({ error: 'Dosya yükleme sırasında beklenmeyen bir hata oluştu.' });
        }

        // Normal işlem akışı
        try {
            const files = req.files;
            const { duration, maxViews, password, e2ee, burn, ownerId } = req.body;

            if (!files || files.length === 0) {
                return res.status(400).json({ error: 'Dosya yüklenmedi.' });
            }

            // Girdi doğrulama ve temizleme
            const validDurations = ['1h', '3h', '24h', '7d'];
            const sanitizedDuration = validDurations.includes(duration) ? duration : '1h';
            const sanitizedMaxViews = Math.max(1, Math.min(1000, parseInt(maxViews) || 1));
            const sanitizedPassword = password ? sanitizeString(password, 128) : '';
            
            // 7 günlük süre sadece üyeler için
            if (sanitizedDuration === '7d' && !ownerId) {
                return res.status(403).json({ error: '7 günlük süre sadece üyeler için geçerlidir.' });
            }
            
            // Toplam dosya boyutu kontrolü: misafir 50MB, üye 100MB
            const totalSize = files.reduce((sum, f) => sum + f.size, 0);
            const isMember = !!ownerId;
            const maxTotalBytes = (isMember ? 100 : 50) * 1024 * 1024;
            if (totalSize > maxTotalBytes) {
                // Yüklenen dosyaları hemen sil
                files.forEach(f => {
                    try {
                        if (fs.existsSync(f.path)) fs.unlinkSync(f.path);
                    } catch (e) {
                        // Dosya silme hatası - sessizce devam et
                    }
                });
                return res.status(400).json({ error: 'Toplam dosya boyutu limiti aşıldı.' });
            }

            // Veritabanı boyut kontrolü
            try {
                const db = require('./src/database/db');
                const dbPath = db.getDbPath ? db.getDbPath() : path.join(storageBase, 'data', 'temp_share.db');
                if (fs.existsSync(dbPath)) {
                    const dbStats = fs.statSync(dbPath);
                    const dbSizeMB = dbStats.size / (1024 * 1024);
                    
                    // Veritabanı 500MB'ı geçerse yeni yükleme yapılamaz
                    if (dbSizeMB > 500) {
                        return res.status(507).json({ error: 'Veritabanı kapasitesi dolmuş. Lütfen daha sonra tekrar deneyin.' });
                    }
                }
            } catch (dbCheckError) {
                // Hata olsa bile devam et
            }

            const uploadedFiles = [];

            for (const file of files) {
                const id = uuidv4();
                
                // Dosya süresini hesapla
                let addMs = 0;
                switch (sanitizedDuration) {
                    case '1h': addMs = 1 * 60 * 60 * 1000; break;
                    case '3h': addMs = 3 * 60 * 60 * 1000; break;
                    case '24h': addMs = 24 * 60 * 60 * 1000; break;
                    case '7d': addMs = 7 * 24 * 60 * 60 * 1000; break;
                    default: addMs = 1 * 60 * 60 * 1000;
                }
                const expiresAt = Date.now() + addMs;
                
                // Güvenli token oluştur
                const token = createSignedToken(id, expiresAt);

                // Şifre varsa hash'le
                let password_hash = null;
                if (sanitizedPassword && sanitizedPassword.trim() !== '') {
                    if (!isValidPassword(sanitizedPassword)) {
                        return res.status(400).json({ error: 'Şifre 6-128 karakter arasında olmalıdır.' });
                    }
                    password_hash = await bcrypt.hash(sanitizedPassword, 10);
                }

                // Dosya adını temizle (güvenlik için)
                const sanitizedFilename = sanitizeString(file.originalname || 'unnamed', 255)
                    .replace(/[\/\\\?\*\|<>:"]/g, '_') // Tehlikeli karakterleri değiştir
                    .replace(/^\.+/, ''); // Başta nokta olmasın
                
                const fileData = {
                    id,
                    token,
                    owner_id: ownerId || null,
                    filename: sanitizedFilename || 'unnamed',
                    filepath: file.path,
                    mime_type: file.mimetype,
                    size_bytes: file.size,
                    password_hash: password_hash,
                    e2ee_enabled: e2ee === 'true' ? 1 : 0,
                    burn_after_download: burn === 'true' ? 1 : 0,
                    download_limit: sanitizedMaxViews, // 1-1000 arası (zaten sanitize edildi)
                    expires_at: expiresAt
                };

                fileManager.insertFile(fileData);
                
                // Log kaydı
                const ownerInfo = ownerId ? `üye: ${userManager.getUserById(ownerId)?.email || 'bilinmeyen'}` : 'misafir';
                const passwordInfo = password_hash ? 'şifreli' : 'şifresiz';
                const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
                console.log(`[UPLOAD] Dosya yüklendi: ${file.originalname} (${sizeMB}MB), ${ownerInfo}, ${passwordInfo}, süre: ${sanitizedDuration}, limit: ${sanitizedMaxViews}`);
                
                // Kullanıcıya token döndür
                uploadedFiles.push({
                    filename: file.originalname,
                    token: token,
                    expiresAt: expiresAt
                });
            }

            res.json({ message: 'Dosyalar yüklendi.', files: uploadedFiles });
        } catch (error) {
            return res.status(500).json({ error: 'Dosya yükleme hatası.' });
        }
    });
});

// 4. Dosya Bilgilerini Getir (İndirme Sayfası İçin)
app.get('/api/files/:token', (req, res) => {
    try {
        const { token } = req.params;
        
        // Token doğrulama
        const verified = verifySignedToken(token);
        if (!verified) {
            return res.status(403).json({ error: 'Geçersiz veya sahte token.' });
        }
        
        // Token'dan dosya ID'sini al
        const file = fileManager.getFileMetadata(verified.fileId);

        if (!file) {
            return res.status(404).json({ error: 'Dosya bulunamadı.' });
        }

        // Dosya durumunu kontrol et (süre, limit)
        const statusCheck = fileManager.checkFileStatus(file.id);
        // SQLite'dan gelen değerler string olabilir, sayıya çevir
        const downloadCount = Number(file.download_count) || 0;
        const downloadLimit = Number(file.download_limit) || 1;
        const expiresAt = Number(file.expires_at) || 0;
        const isExpired = Date.now() > expiresAt;
        const isLimitReached = downloadCount >= downloadLimit;

        // Yükleyen bilgisini hazırla
        let ownerLabel = 'Misafir';
        if (file.owner_id) {
            try {
                const owner = userManager.getUserById(file.owner_id);
                if (owner && owner.name) {
                    ownerLabel = owner.name;
                } else {
                    ownerLabel = 'Üye';
                }
            } catch (e) {
                ownerLabel = 'Üye';
            }
        }

        // Dosya bilgilerini döndür (limit dolmuş olsa bile frontend'e göster)
        res.json({
            filename: file.filename,
            size: file.size_bytes,
            owner: ownerLabel,
            expiresAt: expiresAt,
            isLocked: !!file.password_hash,
            isBurn: !!file.burn_after_download,
            downloadCount: downloadCount,
            downloadLimit: downloadLimit,
            isExpired: isExpired,
            isLimitReached: isLimitReached,
            statusMessage: !statusCheck.status ? statusCheck.message : null
        });

    } catch (error) {
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
});

// 5. Dosya İndirme
app.post('/api/files/:token/download', async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        // Token doğrulama
        const verified = verifySignedToken(token);
        if (!verified) {
            return res.status(403).json({ error: 'Geçersiz veya sahte token.' });
        }
        
        // Token'dan dosya ID'sini al
        const file = fileManager.getFileMetadata(verified.fileId);
        if (!file) {
            return res.status(404).json({ error: 'Dosya bulunamadı.' });
        }

        // Dosya durumunu kontrol et
        const statusCheck = fileManager.checkFileStatus(file.id);
        if (!statusCheck.status) {
            return res.status(410).json({ error: statusCheck.message });
        }

        // Şifre kontrolü
        if (file.password_hash) {
            if (!password) {
                return res.status(403).json({ error: 'Bu dosya şifre korumalı.' });
            }
            const isValid = await bcrypt.compare(password, file.password_hash);
            if (!isValid) {
                return res.status(403).json({ error: 'Hatalı şifre.' });
            }
        }

        // İndirme sayısını artır
        fileManager.incrementDownloadCount(file.id);
        
        // Log kaydı
        const tokenPreview = token.substring(0, 8) + '...';
        const passwordInfo = file.password_hash ? 'şifreli' : 'şifresiz';
        const downloadCount = Number(file.download_count) + 1;
        const downloadLimit = Number(file.download_limit);
        console.log(`[DOWNLOAD] Dosya indirildi: ${file.filename}, token: ${tokenPreview}, ${passwordInfo}, indirme: ${downloadCount}/${downloadLimit}`);

        // İndirme sonrası silme kontrolü
        const willExceedLimit = (file.download_count + 1) >= file.download_limit;
        const shouldBurn = !!file.burn_after_download || willExceedLimit;

        // Dosyayı kullanıcıya gönder
        res.download(file.filepath, file.filename, (err) => {
            if (err) {
                // Hata olsa bile devam et
            }
            // İndirme sonrası silme veya limit dolunca dosyayı sil
            if (shouldBurn) {
                try {
                    fileManager.deleteFileById(file.id);
                } catch (e) {
                    // Silme hatası - devam et
                }
            }
        });

    } catch (error) {
        res.status(500).json({ error: 'İndirme başlatılamadı.' });
    }
});

// 6. Kötüye Kullanım Raporu
app.post('/api/reports', (req, res) => {
    try {
        let { token, title, description } = req.body;

        // Girdi kontrolü ve temizleme
        token = (token || '').trim();
        title = sanitizeString(title || '', 200);
        description = sanitizeString(description || '', 2000);

        if (!token) {
            return res.status(400).json({ error: 'Geçersiz veya eksik token.' });
        }
        if (!title || title.length < 1) {
            return res.status(400).json({ error: 'Başlık 1-200 karakter arasında olmalıdır.' });
        }
        if (!description || description.length < 1) {
            return res.status(400).json({ error: 'Açıklama 1-2000 karakter arasında olmalıdır.' });
        }

        // Token doğrulama (dosya varsa bağlantı kur)
        let file_id = null;
        const verified = verifySignedToken(token);
        if (verified) {
            const file = fileManager.getFileMetadata(verified.fileId);
            if (file) {
                file_id = file.id;
            }
        }
        
        // Dosya silinmiş olsa bile rapor kaydedilebilir

        // Raporu kaydet
        const reportId = reportManager.insertReport({
            file_id: file_id,
            reporter_email: null,
            title,
            description
        });
        
        // Log kaydı
        const fileInfo = file_id ? `dosya_id: ${file_id.substring(0, 8)}...` : 'dosya bulunamadı';
        console.log(`[REPORT] Geri bildirim alındı: "${title}", ${fileInfo}`);

        res.json({ message: 'Rapor iletildi.' });

    } catch (error) {
        res.status(500).json({ error: 'Raporlama hatası.' });
    }
});

// --- SELF-HEALING: Sağlık Kontrolü ---

// Sunucu çalışıyor mu?
app.get('/healthz', (req, res) => {
    res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Sistem hazır mı? (veritabanı, dosya klasörü vb.)
app.get('/readyz', (req, res) => {
    try {
        // Veritabanı bağlantısını test et
        fileManager.getFileMetadata('test');
        
        // Yükleme klasörü erişilebilir mi?
        if (!fs.existsSync(uploadDir)) {
            return res.status(503).json({ status: 'not ready', reason: 'Upload directory not accessible' });
        }

        res.status(200).json({ 
            status: 'ready', 
            timestamp: new Date().toISOString(),
            services: {
                database: 'ok',
                uploads: 'ok'
            }
        });
    } catch (error) {
        res.status(503).json({ 
            status: 'not ready', 
            reason: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// --- SUNUCU BAŞLATMA ---

const server = app.listen(PORT, () => {
    console.log(`🚀 TempShare sunucusu başlatıldı: http://localhost:${PORT}`);
});

// --- SELF-HEALING: Düzgün Kapatma ---
let isShuttingDown = false;

const gracefulShutdown = (signal) => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    
    server.close(() => {
        // Veritabanı bağlantısını kapat
        try {
            const db = require('./src/database/db');
            db.close();
        } catch (e) {
            // Hata olsa bile devam et
        }
        
        process.exit(0);
    });
    
    // 10 saniye sonra zorla kapat
    setTimeout(() => {
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// --- SELF-HEALING: Otomatik Temizlik ---
// Süresi dolmuş dosyaları otomatik temizle (her saat)
setInterval(() => {
    try {
        fileManager.cleanupExpiredFiles();
    } catch (e) {
        // Hata olsa bile devam et
    }
}, 60 * 60 * 1000);
