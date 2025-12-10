const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// Veritabanı dosyasının kaydedileceği yer (bu klasörün içinde data/)
const dbPath = path.join(__dirname, '../../data/temp_share.db');

// data klasörü yoksa oluştur
const dataDir = path.dirname(dbPath);
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(dbPath, { verbose: console.log });
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

console.log('Veritabanı bağlantısı (benim-is) -> ' + dbPath);

// Yalnızca FILES şeması
const createTablesQuery = `
    CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,                         
        token TEXT NOT NULL UNIQUE,                  
        owner_id TEXT,                              
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

    CREATE INDEX IF NOT EXISTS idx_files_expires_at ON files (expires_at);
    CREATE INDEX IF NOT EXISTS idx_files_owner ON files (owner_id);
    CREATE INDEX IF NOT EXISTS idx_files_token ON files (token);
`;
db.exec(createTablesQuery);

// updated_at tetikleyicisi (files)
const triggerQuery = `
    CREATE TRIGGER IF NOT EXISTS trg_files_updated
    AFTER UPDATE ON files
    FOR EACH ROW
    BEGIN
        UPDATE files SET updated_at = strftime('%s','now') WHERE id = OLD.id;
    END;
`;
db.exec(triggerQuery);

console.log('Şema ve tetikleyici (files) hazır.');

module.exports = db;

