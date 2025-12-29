// Abuse report management
const db = require('./db');
const crypto = require('crypto');

const insertReport = ({ file_id, reporter_email, title, description }) => {
    const reportId = crypto.randomUUID();
    const stmt = db.prepare(`
        INSERT INTO abuse_reports (id, file_id, reporter_email, title, description)
        VALUES (@id, @file_id, @reporter_email, @title, @description)
    `);
    stmt.run({
        id: reportId,
        file_id: file_id || null, // Dosya silinmişse null olabilir
        reporter_email: reporter_email || null,
        title,
        description
    });
    return { id: reportId, file_id: file_id || null };
};

const getReportsByFile = (file_id) => {
    const stmt = db.prepare("SELECT * FROM abuse_reports WHERE file_id = ? ORDER BY created_at DESC");
    return stmt.all(file_id);
};

module.exports = {
    insertReport,
    getReportsByFile
};

