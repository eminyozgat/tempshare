const { insertFile, cleanupExpiredFiles, calculateExpiryDate } = require('./src/database/fileManager');
const crypto = require('crypto');
const fs = require('fs');

console.log("--- BENIM-IS: Dosya ekleme + cleanup demo ---");

// Demo: sahte dosya oluşturup süresi geçmiş olarak ekle, sonra cleanup çalıştır
const fakeFilePath = './data/test_dosyasi.txt';
fs.writeFileSync(fakeFilePath, "Bu dosya silinecek!");

const expiredFile = {
    id: crypto.randomUUID(),
    token: crypto.randomUUID().replace(/-/g, ''),
    owner_id: null,
    filename: 'test_dosyasi.txt',
    filepath: fakeFilePath,
    mime_type: 'text/plain',
    size_bytes: fs.statSync(fakeFilePath).size,
    password_hash: null,
    e2ee_enabled: 0,
    burn_after_download: 0,
    download_limit: 1,
    expires_at: Date.now() - 10000 // 10 saniye önce süresi dolmuş
};

insertFile(expiredFile);
console.log("✅ Süresi geçmiş dosya eklendi.");

cleanupExpiredFiles();
console.log("🧹 Cleanup tamamlandı.");

console.log("Örnek 7g bitiş:", new Date(calculateExpiryDate('7d')).toISOString());

