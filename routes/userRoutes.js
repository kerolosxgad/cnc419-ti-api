const express = require('express');
const router = express.Router();
const { isAuthenticated } = require('../middleware/authentication');
const upload = require('../middleware/upload');
const userController = require('../controllers/userController');

// User routes
router.post('/get', isAuthenticated, userController.getUser);
router.post('/update', isAuthenticated, userController.updateUser);
router.post('/update-image', isAuthenticated, upload.single('image'), userController.updateImage);
router.post('/delete', isAuthenticated, userController.deleteUser);

module.exports = router;
