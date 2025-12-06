function isAuthorized (...allowedRoles) {
    // If called without args (app.use(isAuthorized)), default to ['admin']
    let roles;
    if (allowedRoles.length === 0) {
        roles = ['admin'];
    } else if (allowedRoles.length === 1 && Array.isArray(allowedRoles[0])) {
        roles = allowedRoles[0];
    } else {
        roles = allowedRoles;
    }

    // Normalize roles for case-insensitive comparison
    const normalizedRoles = roles.map(r => String(r).toLowerCase());

    return (req, res, next) => {
        if (!req.user || !req.user.role) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const userRole = String(req.user.role).toLowerCase();
        if (normalizedRoles.includes(userRole)) {
            return next();
        }

        return res.status(403).json({ message: 'Forbidden' });
    };
}

module.exports = { isAuthorized };
