// User authentication and management
const db = require('./db');
const bcrypt = require('bcryptjs');

const createUser = async ({ id, name, email, password }) => {
    const password_hash = await bcrypt.hash(password, 10);
    const stmt = db.prepare(`
        INSERT INTO users (id, name, email, password_hash)
        VALUES (@id, @name, @email, @password_hash)
    `);
    return stmt.run({ id, name, email, password_hash });
};

const getUserByEmail = (email) => {
    const stmt = db.prepare("SELECT * FROM users WHERE email = ?");
    return stmt.get(email);
};

const getUserById = (id) => {
    const stmt = db.prepare("SELECT * FROM users WHERE id = ?");
    return stmt.get(id);
};

const verifyPassword = async (user, plainPassword) => {
    if (!user) return false;
    return bcrypt.compare(plainPassword, user.password_hash);
};

const touchLastLogin = (id) => {
    const stmt = db.prepare("UPDATE users SET last_login_at = strftime('%s','now'), updated_at = strftime('%s','now') WHERE id = ?");
    stmt.run(id);
};

module.exports = {
    createUser,
    getUserByEmail,
    getUserById,
    verifyPassword,
    touchLastLogin
};

