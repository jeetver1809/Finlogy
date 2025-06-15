const express = require('express');
const {
  getSummary,
  getMonthlyAnalysis,
  getCategoryAnalysis,
} = require('../controllers/analyticsController');
const { protect } = require('../middleware/auth');

const router = express.Router();

// All routes are protected
router.use(protect);

router.get('/summary', getSummary);
router.get('/monthly', getMonthlyAnalysis);
router.get('/category', getCategoryAnalysis);

module.exports = router;
