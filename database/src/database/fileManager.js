const db = require('./db');
const fs = require('fs'); // Dosyayı diskten silmek için gerekli

// --- YARDIMCI MANTIK ---
const calculateExpiryDate = (durationString) => {
    const now = Date.now();
    let addMs = 0;
    switch (durationString) {
        case '1h': addMs = 1 * 60 * 60 * 1000; break;
        case '3h': addMs = 3 * 60 * 60 * 1000; break;
        case '24h': addMs = 24 * 60 * 60 * 1000; break;
        case '7d': addMs = 7 * 24 * 60 * 60 * 1000; break;
        default: addMs = 1 * 60 * 60 * 1000;
    }
    return now + addMs;
};

// --- ANA FONKSİYONLAR ---

// 1. Dosya Ekle
const insertFile = (fileData) => {
    try {
        const stmt = db.prepare(`
            INSERT INTO files (
                id, token, owner_id, filename, filepath, mime_type, size_bytes,
                password_hash, e2ee_enabled, burn_after_download,
                download_limit, download_count, expires_at
            ) 
            VALUES (
                @id, @token, @owner_id, @filename, @filepath, @mime_type, @size_bytes,
                @password_hash, @e2ee_enabled, @burn_after_download,
                @download_limit, @download_count, @expires_at
            )
        `);
        return stmt.run({
            download_count: 0,
            burn_after_download: 0,
            e2ee_enabled: 0,
            ...fileData
        });
    } catch (error) {
        throw error;
    }
};

// 2. Dosya Bilgisi Çek
const getFileMetadata = (fileId) => {
    try {
        const stmt = db.prepare('SELECT * FROM files WHERE id = ?');
        return stmt.get(fileId);
    } catch (error) {
        return null;
    }
};

// 2b. Token ile dosya bilgisi çek
const getFileByToken = (token) => {
    try {
        const stmt = db.prepare('SELECT * FROM files WHERE token = ?');
        return stmt.get(token);
    } catch (error) {
        return null;
    }
};

// 3. Durum Kontrolü (İndirilebilir mi?)
const checkFileStatus = (fileId) => {
    const file = getFileMetadata(fileId);
    if (!file) return { status: false, message: "Dosya bulunamadı." };

    if (file.download_count >= file.download_limit) {
        return { status: false, message: "İndirme limitine ulaşıldı." };
    }
    
    if (Date.now() > file.expires_at) {
        return { status: false, message: "Dosyanın süresi dolmuş." };
    }

    return { status: true, file: file };
};

// 4. İndirme Sayısını Artır
const incrementDownloadCount = (fileId) => {
    const stmt = db.prepare("UPDATE files SET download_count = download_count + 1 WHERE id = ?");
    stmt.run(fileId);
};

// 5. Şifre hash'i çek
const getFilePasswordHash = (fileId) => {
    const stmt = db.prepare("SELECT password_hash FROM files WHERE id = ?");
    return stmt.get(fileId);
};

// Yardımcı: tek bir dosyayı (disk + DB) kalıcı sil
const deleteFileById = (fileId) => {
    const file = getFileMetadata(fileId);
    if (!file) return;

    const deleteStmt = db.prepare("DELETE FROM files WHERE id = ?");
    try {
        if (fs.existsSync(file.filepath)) {
            fs.unlinkSync(file.filepath);
            console.log(`🗑️ Diskten silindi: ${file.filename}`);
        }
    } catch (err) {
        console.error(`Hata (Dosya Silme): ${file.filename}`, err.message);
    }

    deleteStmt.run(file.id);
    console.log(`❌ Kayıt silindi: ${file.id}`);
};

// 6. Cleanup – süresi dolmuş dosyaları toplu temizle
const cleanupExpiredFiles = () => {
    const now = Date.now();
    const expiredFiles = db.prepare("SELECT * FROM files WHERE expires_at < ?").all(now);

    if (expiredFiles.length > 0) {
        console.log(`🧹 Temizlik Başladı: ${expiredFiles.length} adet süresi dolmuş dosya bulundu.`);
        expiredFiles.forEach(file => deleteFileById(file.id));
    }
};

module.exports = { 
    insertFile, 
    getFileMetadata, 
    getFileByToken,
    checkFileStatus, 
    calculateExpiryDate,
    incrementDownloadCount,
    cleanupExpiredFiles,
    getFilePasswordHash,
    deleteFileById
};

