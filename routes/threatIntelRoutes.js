const express = require('express');
const router = express.Router();
const { isAuthenticated } = require('../middleware/authentication');
const threatIntelController = require('../controllers/threatIntelController');

// Middleware to check if user is admin
const requireAdmin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    return next();
  }
  return res.status(403).json({ success: false, message: 'Admin access required' });
};

// Search and Query Routes
router.get('/search', isAuthenticated, threatIntelController.searchIOCs);
router.get('/ioc/:id', isAuthenticated, threatIntelController.getIOCDetails);
router.get('/correlate', isAuthenticated, threatIntelController.correlateIOCs);

// Statistics and Reports
router.get('/statistics', isAuthenticated, threatIntelController.getStatistics);
router.get('/report/summary', isAuthenticated, threatIntelController.getSummaryReport);

// Feed Management (Admin only)
router.post('/ingest', isAuthenticated, requireAdmin, threatIntelController.triggerIngestion);
router.get('/fetch-status', isAuthenticated, requireAdmin, threatIntelController.getFetchStatus);

module.exports = router;
