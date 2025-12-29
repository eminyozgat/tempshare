// Database connection and initialization
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// Veritabanı dosyasının yolu
// Railway'de tek volume kullanıyoruz: /app/storage
// Local'de proje klasörü içinde data/ klasörü
const storageBase = process.env.STORAGE_BASE || path.join(__dirname, '../../');
const dbDir = path.join(storageBase, 'data');
const dbPath = path.join(dbDir, 'temp_share.db');

// Klasör yoksa oluştur
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

const db = new Database(dbPath);
db.pragma('journal_mode = WAL'); // Write-Ahead Logging modu
db.pragma('foreign_keys = ON'); // Foreign key kontrolünü aç

// Veritabanı tablolarını oluştur
const createTablesQuery = `
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at INTEGER DEFAULT (strftime('%s','now')),
        updated_at INTEGER DEFAULT (strftime('%s','now')),
        last_login_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        token TEXT NOT NULL UNIQUE,
        owner_id TEXT REFERENCES users(id) ON DELETE SET NULL,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        mime_type TEXT,
        size_bytes INTEGER,
        password_hash TEXT,
        e2ee_enabled INTEGER DEFAULT 0,
        burn_after_download INTEGER DEFAULT 0,
        download_limit INTEGER NOT NULL DEFAULT 1 CHECK (download_limit > 0),
        download_count INTEGER NOT NULL DEFAULT 0 CHECK (download_count >= 0),
        expires_at INTEGER NOT NULL,
        created_at INTEGER DEFAULT (strftime('%s','now')),
        updated_at INTEGER DEFAULT (strftime('%s','now'))
    );

    CREATE TABLE IF NOT EXISTS abuse_reports (
        id TEXT PRIMARY KEY,
        file_id TEXT REFERENCES files(id) ON DELETE CASCADE,
        reporter_email TEXT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        created_at INTEGER DEFAULT (strftime('%s','now'))
    );

    CREATE INDEX IF NOT EXISTS idx_files_expires_at ON files (expires_at);
    CREATE INDEX IF NOT EXISTS idx_files_owner ON files (owner_id);
    CREATE INDEX IF NOT EXISTS idx_files_token ON files (token);
    CREATE INDEX IF NOT EXISTS idx_abuse_file ON abuse_reports (file_id);
`;
db.exec(createTablesQuery);

// Otomatik güncelleme tetikleyicileri
const triggerQuery = `
    CREATE TRIGGER IF NOT EXISTS trg_users_updated
    AFTER UPDATE ON users
    FOR EACH ROW
    BEGIN
        UPDATE users SET updated_at = strftime('%s','now') WHERE id = OLD.id;
    END;

    CREATE TRIGGER IF NOT EXISTS trg_files_updated
    AFTER UPDATE ON files
    FOR EACH ROW
    BEGIN
        UPDATE files SET updated_at = strftime('%s','now') WHERE id = OLD.id;
    END;
`;
db.exec(triggerQuery);

// Veritabanı hazır

module.exports = db;
module.exports.getDbPath = () => dbPath; // Veritabanı dosya yolunu döndür
module.exports.close = () => db.close(); // Veritabanı bağlantısını kapat

