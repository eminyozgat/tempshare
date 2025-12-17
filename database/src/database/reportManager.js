const db = require('./db');
const crypto = require('crypto');

const insertReport = ({ file_id, reporter_email, title, description }) => {
    const stmt = db.prepare(`
        INSERT INTO abuse_reports (id, file_id, reporter_email, title, description)
        VALUES (@id, @file_id, @reporter_email, @title, @description)
    `);
    return stmt.run({
        id: crypto.randomUUID(),
        file_id,
        reporter_email: reporter_email || null,
        title,
        description
    });
};

const getReportsByFile = (file_id) => {
    const stmt = db.prepare("SELECT * FROM abuse_reports WHERE file_id = ? ORDER BY created_at DESC");
    return stmt.all(file_id);
};

module.exports = {
    insertReport,
    getReportsByFile
};

