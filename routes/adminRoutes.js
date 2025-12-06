const express = require('express');
const router = express.Router();
const { isAuthenticated } = require('../middleware/authentication');
const { isAuthorized } = require('../middleware/authorization');
const upload = require('../middleware/upload');
const adminController = require('../controllers/adminController');

// User Management Routes
router.post('/get-user', isAuthenticated, isAuthorized(), adminController.getUser);
router.post('/edit-role', isAuthenticated, isAuthorized(), adminController.editRole);
router.post('/edit-status', isAuthenticated, isAuthorized(), adminController.editStatus);
router.get('/list-users', isAuthenticated, isAuthorized(), adminController.listUsers);

module.exports = router;
