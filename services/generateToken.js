const jwt = require('jsonwebtoken');
require('dotenv').config();

const { JWT_SECRET } = require('../config/keys');

const ACCESS_TTL = process.env.JWT_EXPIRATION || '15m';

function generateToken(user) {
    const payload = { sub: user.id, uname: user.username, role: user.role, ver: user.tokenVersion };

    return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TTL });
}

module.exports = { generateToken };
