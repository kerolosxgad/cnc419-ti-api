const express = require('express');
const router = express.Router();
const { isAuthenticated } = require('../middleware/authentication');
const authController = require('../controllers/authController');

// Register route
router.post('/register', isAuthenticated, authController.register);

// Login route
router.post('/login', isAuthenticated, authController.login);

// Verify OTP route
router.post('/verify-otp', isAuthenticated, authController.verifyOTP);

// Resend OTP route
router.post('/resend-otp', isAuthenticated, authController.resendOTP);

// Forgot password route
router.post('/reset-password', isAuthenticated, authController.resetPassword);

// Logout route
router.post('/logout', isAuthenticated, authController.logout);

// Check route
router.get('/check', isAuthenticated, authController.check);

module.exports = router;
