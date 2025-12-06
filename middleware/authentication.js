const jwt = require('jsonwebtoken');
const { API_KEY, JWT_SECRET } = require('../config/keys');
const { User } = require('../models/user');

async function isAuthenticated(req, res, next) {
    const apiKey = req.headers['api-key'] || req.query['api-key'];
    if (apiKey && apiKey === API_KEY) return next();

    const authHeader = req.headers.authorization || '';
    const [, token] = authHeader.split(' ');

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
        if (err) {
            const msg = err.name === 'TokenExpiredError'
                ? 'Session expired, please log in again'
                : 'Unauthorized';
            return res.status(401).json({ message: msg });
        }

        try {
            const user = await User.findByPk(decoded.sub, { attributes: ['tokenVersion'] });

            if (!user || user.tokenVersion !== decoded.ver) {
                return res.status(401).json({ message: 'Session invalid or canceled' });
            }

            req.user = decoded;
            next();
        } catch (error) {
            console.error('Error fetching user:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    });
}

module.exports = { isAuthenticated };
