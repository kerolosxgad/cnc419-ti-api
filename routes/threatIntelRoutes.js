const express = require('express');
const router = express.Router();
const { isAuthenticated } = require('../middleware/authentication');
const { isAuthorized } = require('../middleware/authorization');
const threatIntelController = require('../controllers/threatIntelController');

// Search and Query Routes
router.post('/search', isAuthenticated, threatIntelController.searchIOCs);
router.post('/ioc', isAuthenticated, threatIntelController.getIOCDetails);
router.post('/correlate', isAuthenticated, threatIntelController.correlateIOCs);

// Statistics and Reports
router.get('/statistics', isAuthenticated, threatIntelController.getStatistics);
router.post('/report-summary', isAuthenticated, threatIntelController.getSummaryReport);

// Feed Management (Admin only)
router.post('/ingest', isAuthenticated, isAuthorized(), threatIntelController.triggerIngestion);
router.get('/fetch-status', isAuthenticated, isAuthorized(), threatIntelController.getFetchStatus);

module.exports = router;
