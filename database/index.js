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

// Managers
const userManager = require('./src/database/userManager');
const fileManager = require('./src/database/fileManager');
const reportManager = require('./src/database/reportManager');

const app = express();
const PORT = process.env.PORT || 3000;

// HMAC Secret Key (production'da environment variable'dan alınmalı)
const HMAC_SECRET = process.env.HMAC_SECRET || 'temp-share-secret-key-change-in-production';

// HMAC-signed token oluştur
const createSignedToken = (fileId, expiresAt) => {
    const payload = `${fileId}:${expiresAt}`;
    const signature = crypto.createHmac('sha256', HMAC_SECRET)
        .update(payload)
        .digest('hex');
    const token = Buffer.from(payload).toString('base64url');
    return `${token}.${signature}`;
};

// HMAC-signed token doğrula
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

// --- INPUT VALIDATION HELPERS ---

// Email format validation
const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 255;
};

// String sanitization (XSS koruması - HTML escape)
const sanitizeString = (str, maxLength = 1000) => {
    if (typeof str !== 'string') return '';
    return str
        .trim()
        .substring(0, maxLength)
        .replace(/[<>]/g, ''); // Basit XSS koruması
};

// Name validation (alfanumerik + boşluk + Türkçe karakterler)
const isValidName = (name) => {
    if (!name || typeof name !== 'string') return false;
    const trimmed = name.trim();
    if (trimmed.length < 2 || trimmed.length > 100) return false;
    // Alfanumerik, boşluk, Türkçe karakterler ve bazı özel karakterler
    const nameRegex = /^[a-zA-ZğüşıöçĞÜŞİÖÇ\s\-'\.]+$/;
    return nameRegex.test(trimmed);
};

// Password validation
const isValidPassword = (password) => {
    if (!password || typeof password !== 'string') return false;
    return password.length >= 6 && password.length <= 128;
};

// Middleware

// CORS: prod'da tek origin'e sabitlemek için ALLOWED_ORIGIN kullan
const allowedOrigin = process.env.ALLOWED_ORIGIN;
if (allowedOrigin) {
    app.use(cors({ origin: allowedOrigin }));
} else {
    app.use(cors());
}

// Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"], // CSS için inline gerekli
            scriptSrc: ["'self'", "'unsafe-inline'"], // JS için inline gerekli
            imgSrc: ["'self'", "data:", "https://api.qrserver.com"], // QR kod için
            connectSrc: ["'self'"]
        }
    },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    noSniff: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 20,
    standardHeaders: true,
    legacyHeaders: false
});

const downloadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 100,
    standardHeaders: true,
    legacyHeaders: false
});

app.use('/api/auth/', authLimiter);
app.use('/api/files/', downloadLimiter);

// Static Files (Frontend)
// Dockerfile'da public/ klasörü /app/public/ olarak kopyalanıyor
// Local'de ../public, Railway'de ./public (Dockerfile'da zaten ./public/ olarak kopyalanıyor)
// Railway'de __dirname = /app, bu yüzden ./public kullanmalıyız
const publicDir = fs.existsSync(path.join(__dirname, './public')) 
    ? path.join(__dirname, './public') 
    : path.join(__dirname, '../public');
app.use(express.static(publicDir));

// Uploads Directory - Railway'de tek volume: /app/storage (içinde uploads/ klasörü)
// Local'de: ../uploads
// Railway'de STORAGE_BASE=/app/storage olarak ayarlanmalı
const storageBase = process.env.STORAGE_BASE || path.join(__dirname, '../');
const uploadDir = path.join(storageBase, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname);
    }
});

// Her dosya için üst sınır: 100MB (üyeler için maksimum)
// Dosya türü kontrolü kaldırıldı - tüm dosya türleri kabul edilir
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 100 * 1024 * 1024 // 100MB
    }
    // fileFilter kaldırıldı - tüm dosya türleri kabul edilir
});

// --- API ROUTES ---

// 1. Auth: Register
app.post('/api/auth/register', async (req, res) => {
    try {
        let { name, email, password } = req.body;
        
        // Input validation
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Tüm alanlar zorunludur.' });
        }
        
        // Sanitize inputs
        name = sanitizeString(name, 100);
        email = email.trim().toLowerCase();
        password = password.trim();
        
        // Validate name
        if (!isValidName(name)) {
            return res.status(400).json({ error: 'Geçersiz isim. İsim 2-100 karakter arasında olmalı ve sadece harf, boşluk ve bazı özel karakterler içermelidir.' });
        }
        
        // Validate email
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: 'Geçersiz e-posta adresi.' });
        }
        
        // Validate password
        if (!isValidPassword(password)) {
            return res.status(400).json({ error: 'Şifre 6-128 karakter arasında olmalıdır.' });
        }

        const existingUser = userManager.getUserByEmail(email);
        if (existingUser) {
            return res.status(400).json({ error: 'Bu e-posta adresi zaten kayıtlı.' });
        }

        const id = uuidv4();
        await userManager.createUser({ id, name, email, password });
        
        // Auto login after register
        const user = userManager.getUserById(id);
        res.status(201).json({ message: 'Kayıt başarılı.', user: { id: user.id, name: user.name, email: user.email } });
    } catch (error) {
        res.status(500).json({ error: 'Kayıt sırasında bir hata oluştu.' });
    }
});

// 2. Auth: Login
app.post('/api/auth/login', async (req, res) => {
    try {
        let { email, password } = req.body;
        
        // Input validation
        if (!email || !password) {
            return res.status(400).json({ error: 'E-posta ve şifre zorunludur.' });
        }
        
        // Sanitize inputs
        email = email.trim().toLowerCase();
        password = password.trim();
        
        // Validate email format
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: 'Geçersiz e-posta adresi.' });
        }
        
        // Validate password
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
        res.json({ message: 'Giriş başarılı.', user: { id: user.id, name: user.name, email: user.email } });
    } catch (error) {
        res.status(500).json({ error: 'Giriş sırasında bir hata oluştu.' });
    }
});

// 3. File Upload (multer özel hata yönetimi ile)
const uploadMiddleware = upload.array('file[]');

app.post('/api/upload', (req, res) => {
    uploadMiddleware(req, res, async (err) => {
        // Multer kaynaklı hatalar
        if (err) {
            if (err instanceof multer.MulterError) {
                if (err.code === 'LIMIT_FILE_SIZE') {
                    return res.status(400).json({ error: 'Dosya boyutu çok büyük. Maksimum 100MB.' });
                }
                return res.status(400).json({ error: 'Dosya yükleme hatası (Multer).' });
            }
            // Dosya türü kontrolü kaldırıldı 
            return res.status(500).json({ error: 'Dosya yükleme sırasında beklenmeyen bir hata oluştu.' });
        }

        // Normal iş akışı
        try {
            const files = req.files;
            const { duration, maxViews, password, e2ee, burn, ownerId } = req.body;

            if (!files || files.length === 0) {
                return res.status(400).json({ error: 'Dosya yüklenmedi.' });
            }

            // Input validation
            const validDurations = ['1h', '3h', '24h', '7d'];
            const sanitizedDuration = validDurations.includes(duration) ? duration : '1h';
            const sanitizedMaxViews = Math.max(1, Math.min(1000, parseInt(maxViews) || 1));
            const sanitizedPassword = password ? sanitizeString(password, 128) : '';
            
            // Üye kontrolü - 7 gün sadece üyeler için
            if (sanitizedDuration === '7d' && !ownerId) {
                return res.status(403).json({ error: '7 günlük süre sadece üyeler için geçerlidir.' });
            }
            
            // Toplam boyut limiti: misafir 50MB, üye 100MB
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

            // Veritabanı boyut kontrolü (SQLite için)
            try {
                const dbPath = path.join(__dirname, '../data/temp_share.db');
                if (fs.existsSync(dbPath)) {
                    const dbStats = fs.statSync(dbPath);
                    const dbSizeMB = dbStats.size / (1024 * 1024);
                    
                    // SQLite veritabanı 500MB'ı geçerse uyarı ver (Railway free tier için)
                    if (dbSizeMB > 500) {
                        return res.status(507).json({ error: 'Veritabanı kapasitesi dolmuş. Lütfen daha sonra tekrar deneyin.' });
                    }
                }
            } catch (dbCheckError) {
                // Veritabanı kontrolü başarısız olursa devam et
            }

            const uploadedFiles = [];

            for (const file of files) {
                const id = uuidv4();
                
                // Calculate expiry
                let addMs = 0;
                switch (sanitizedDuration) {
                    case '1h': addMs = 1 * 60 * 60 * 1000; break;
                    case '3h': addMs = 3 * 60 * 60 * 1000; break;
                    case '24h': addMs = 24 * 60 * 60 * 1000; break;
                    case '7d': addMs = 7 * 24 * 60 * 60 * 1000; break;
                    default: addMs = 1 * 60 * 60 * 1000;
                }
                const expiresAt = Date.now() + addMs;
                
                // HMAC-signed token oluştur
                const token = createSignedToken(id, expiresAt);

                // Hash password if provided
                let password_hash = null;
                if (sanitizedPassword && sanitizedPassword.trim() !== '') {
                    if (!isValidPassword(sanitizedPassword)) {
                        return res.status(400).json({ error: 'Şifre 6-128 karakter arasında olmalıdır.' });
                    }
                    password_hash = await bcrypt.hash(sanitizedPassword, 10);
                }

                // Dosya adı sanitization (XSS ve path traversal koruması)
                const sanitizedFilename = sanitizeString(file.originalname || 'unnamed', 255)
                    .replace(/[\/\\\?\*\|<>:"]/g, '_') // Tehlikeli karakterleri temizle
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
                
                // HMAC-signed token'ı kullanıcıya döndür (veritabanında da saklanır)
                uploadedFiles.push({
                    filename: file.originalname,
                    token: token, // HMAC-signed token
                    expiresAt: expiresAt
                });
            }

            res.json({ message: 'Dosyalar yüklendi.', files: uploadedFiles });
        } catch (error) {
            return res.status(500).json({ error: 'Dosya yükleme hatası.' });
        }
    });
});

// 4. Get File Metadata (for Download Page)
app.get('/api/files/:token', (req, res) => {
    try {
        const { token } = req.params;
        
        // HMAC token doğrulama
        const verified = verifySignedToken(token);
        if (!verified) {
            return res.status(403).json({ error: 'Geçersiz veya sahte token.' });
        }
        
        // Token'dan file ID'yi al
        const file = fileManager.getFileMetadata(verified.fileId);

        if (!file) {
            return res.status(404).json({ error: 'Dosya bulunamadı.' });
        }

        // Check status (expiry, limit) - ama metadata'yı her zaman döndür
        const statusCheck = fileManager.checkFileStatus(file.id);
        // SQLite'dan gelen değerler string olabilir, sayıya çevir
        const downloadCount = Number(file.download_count) || 0;
        const downloadLimit = Number(file.download_limit) || 1;
        const expiresAt = Number(file.expires_at) || 0;
        const isExpired = Date.now() > expiresAt;
        const isLimitReached = downloadCount >= downloadLimit;

        // Yükleyen bilgisini hazırla: misafir ise "Misafir",
        // kayıtlı kullanıcı ise doğrudan kullanıcı adı.
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

        // Return safe metadata (limit dolmuş olsa bile döndür, frontend göstersin)
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

// 5. Download File
app.post('/api/files/:token/download', async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        // HMAC token doğrulama
        const verified = verifySignedToken(token);
        if (!verified) {
            return res.status(403).json({ error: 'Geçersiz veya sahte token.' });
        }
        
        // Token'dan file ID'yi al
        const file = fileManager.getFileMetadata(verified.fileId);
        if (!file) {
            return res.status(404).json({ error: 'Dosya bulunamadı.' });
        }

        const statusCheck = fileManager.checkFileStatus(file.id);
        if (!statusCheck.status) {
            return res.status(410).json({ error: statusCheck.message });
        }

        // Password Check
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

        // Burn-after-download veya limit dolumu kontrolü
        const willExceedLimit = (file.download_count + 1) >= file.download_limit;
        const shouldBurn = !!file.burn_after_download || willExceedLimit;

        // Dosyayı gönder
        res.download(file.filepath, file.filename, (err) => {
            if (err) {
                // Download error - sessizce devam et
            }
            // Burn-after-download veya limit dolunca dosyayı kalıcı sil
            if (shouldBurn) {
                try {
                    fileManager.deleteFileById(file.id);
                } catch (e) {
                    // Silme hatası - sessizce devam et
                }
            }
        });

    } catch (error) {
        res.status(500).json({ error: 'İndirme başlatılamadı.' });
    }
});

// 6. Report Abuse
app.post('/api/reports', (req, res) => {
    try {
        let { token, title, description } = req.body;

        // Input validation ve sanitization
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

        // HMAC token doğrulama (rapor için)
        let file_id = null;
        const verified = verifySignedToken(token);
        if (verified) {
            const file = fileManager.getFileMetadata(verified.fileId);
            if (file) {
                file_id = file.id;
            }
        }
        
        // Dosya bulunamazsa bile rapor kaydedilebilir (dosya silinmiş olabilir)

        // Rapor kaydet
        reportManager.insertReport({
            file_id: file_id,
            reporter_email: null, // Optional
            title,
            description
        });

        res.json({ message: 'Rapor iletildi.' });

    } catch (error) {
        res.status(500).json({ error: 'Raporlama hatası.' });
    }
});

// --- SELF-HEALING: Health Check Endpoints ---

// Health check: Sunucu çalışıyor mu?
app.get('/healthz', (req, res) => {
    res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Readiness check: Veritabanı bağlantısı ve servisler hazır mı?
app.get('/readyz', (req, res) => {
    try {
        // Veritabanı bağlantısını test et (fileManager üzerinden)
        fileManager.getFileMetadata('test'); // Bu null döner ama DB bağlantısını test eder
        
        // Upload klasörü erişilebilir mi?
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

// --- SERVER STARTUP ---

const server = app.listen(PORT, () => {
    // Server started
});

// --- SELF-HEALING: Graceful Shutdown ---
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
            // Database close error - sessizce devam et
        }
        
        process.exit(0);
    });
    
    // Force shutdown after 10 seconds
    setTimeout(() => {
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// --- SELF-HEALING: Automatic Cleanup ---
// Süresi dolmuş dosyalar için periyodik temizlik (saatte bir)
setInterval(() => {
    try {
        fileManager.cleanupExpiredFiles();
    } catch (e) {
        // Cleanup error - sessizce devam et
    }
}, 60 * 60 * 1000);

