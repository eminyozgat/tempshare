const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Managers
const userManager = require('./src/database/userManager');
const fileManager = require('./src/database/fileManager');
const reportManager = require('./src/database/reportManager');

const app = express();
const PORT = 3000;

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
    contentSecurityPolicy: false // Şimdilik kapalı; ileride sıkılaştırılabilir
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
app.use(express.static(path.join(__dirname, '../public')));

// Uploads Directory
const uploadDir = path.join(__dirname, '../uploads');
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
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 100 * 1024 * 1024 // 100MB
    },
    fileFilter: (req, file, cb) => {
        // Temel whitelist: görüntü, pdf, metin, zip
        const mime = file.mimetype || '';
        const ext = path.extname(file.originalname || '').toLowerCase();

        const isImage = mime.startsWith('image/');
        const isPdf = mime === 'application/pdf' || ext === '.pdf';
        const isText = mime.startsWith('text/');
        const isZip = (
            mime === 'application/zip' ||
            mime === 'application/x-zip-compressed' ||
            ext === '.zip'
        );

        if (isImage || isPdf || isText || isZip) {
            return cb(null, true);
        }

        return cb(new Error('İzin verilmeyen dosya türü.'), false);
    }
});

// --- API ROUTES ---

// 1. Auth: Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Tüm alanlar zorunludur.' });
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
        console.error('Register Error:', error);
        res.status(500).json({ error: 'Kayıt sırasında bir hata oluştu.' });
    }
});

// 2. Auth: Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
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
        console.error('Login Error:', error);
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
            if (err.message === 'İzin verilmeyen dosya türü.') {
                return res.status(400).json({ error: 'İzin verilmeyen dosya türü.' });
            }
            console.error('Upload Middleware Error:', err);
            return res.status(500).json({ error: 'Dosya yükleme sırasında beklenmeyen bir hata oluştu.' });
        }

        // Normal iş akışı
        try {
            const files = req.files;
            const { duration, maxViews, password, e2ee, burn, ownerId } = req.body;

            if (!files || files.length === 0) {
                return res.status(400).json({ error: 'Dosya yüklenmedi.' });
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
                        console.error('Limit aşımı silme hatası:', e);
                    }
                });
                return res.status(400).json({ error: 'Toplam dosya boyutu limiti aşıldı.' });
            }

            const uploadedFiles = [];

            for (const file of files) {
                const id = uuidv4();
                const token = uuidv4(); // Simple token for URL

                // Calculate expiry
                let addMs = 0;
                switch (duration) {
                    case '1h': addMs = 1 * 60 * 60 * 1000; break;
                    case '3h': addMs = 3 * 60 * 60 * 1000; break;
                    case '24h': addMs = 24 * 60 * 60 * 1000; break;
                    case '7d': addMs = 7 * 24 * 60 * 60 * 1000; break;
                    default: addMs = 1 * 60 * 60 * 1000;
                }
                const expiresAt = Date.now() + addMs;

                // Hash password if provided
                let password_hash = null;
                if (password && password.trim() !== '') {
                    password_hash = await bcrypt.hash(password, 10);
                }

                const fileData = {
                    id,
                    token,
                    owner_id: ownerId || null,
                    filename: file.originalname,
                    filepath: file.path,
                    mime_type: file.mimetype,
                    size_bytes: file.size,
                    password_hash: password_hash,
                    e2ee_enabled: e2ee === 'true' ? 1 : 0,
                    burn_after_download: burn === 'true' ? 1 : 0,
                    download_limit: parseInt(maxViews) || 1,
                    expires_at: expiresAt
                };

                fileManager.insertFile(fileData);

                uploadedFiles.push({
                    filename: file.originalname,
                    token: token,
                    expiresAt: expiresAt
                });
            }

            res.json({ message: 'Dosyalar yüklendi.', files: uploadedFiles });
        } catch (error) {
            console.error('Upload Error:', error);
            return res.status(500).json({ error: 'Dosya yükleme hatası.' });
        }
    });
});

// 4. Get File Metadata (for Download Page)
app.get('/api/files/:token', (req, res) => {
    try {
        const { token } = req.params;
        const file = fileManager.getFileByToken(token);

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
                console.error('Owner fetch error:', e);
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
        console.error('Metadata Error:', error);
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
});

// 5. Download File
app.post('/api/files/:token/download', async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        const file = fileManager.getFileByToken(token);
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
                console.error('Download Error:', err);
            }
            // Burn-after-download veya limit dolunca dosyayı kalıcı sil
            if (shouldBurn) {
                try {
                    fileManager.deleteFileById(file.id);
                } catch (e) {
                    console.error('Burn-after-download silme hatası:', e);
                }
            }
        });

    } catch (error) {
        console.error('Download Action Error:', error);
        res.status(500).json({ error: 'İndirme başlatılamadı.' });
    }
});

// 6. Report Abuse
app.post('/api/reports', (req, res) => {
    try {
        let { token, title, description } = req.body;

        // Basit validation ve trim
        token = (token || '').trim();
        title = (title || '').trim();
        description = (description || '').trim();

        if (!token) {
            return res.status(400).json({ error: 'Geçersiz veya eksik token.' });
        }
        if (!title || title.length > 200) {
            return res.status(400).json({ error: 'Başlık 1-200 karakter arasında olmalıdır.' });
        }
        if (!description || description.length > 2000) {
            return res.status(400).json({ error: 'Açıklama 1-2000 karakter arasında olmalıdır.' });
        }

        const file = fileManager.getFileByToken(token);

        if (!file) {
            return res.status(404).json({ error: 'Dosya bulunamadı.' });
        }

        reportManager.insertReport({
            file_id: file.id,
            reporter_email: null, // Optional
            title,
            description
        });

        res.json({ message: 'Rapor iletildi.' });

    } catch (error) {
        console.error('Report Error:', error);
        res.status(500).json({ error: 'Raporlama hatası.' });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});

// Süresi dolmuş dosyalar için periyodik temizlik (saatte bir)
setInterval(() => {
    try {
        fileManager.cleanupExpiredFiles();
    } catch (e) {
        console.error('Cleanup job hatası:', e);
    }
}, 60 * 60 * 1000);
