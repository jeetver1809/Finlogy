const express = require('express');
const {
  getIncome,
  getIncomeEntry,
  createIncome,
  updateIncome,
  deleteIncome,
} = require('../controllers/incomeController');
const { protect } = require('../middleware/auth');
const { validateIncome } = require('../middleware/validation');

const router = express.Router();

// All routes are protected
router.use(protect);

router.route('/')
  .get(getIncome)
  .post(validateIncome, createIncome);

router.route('/:id')
  .get(getIncomeEntry)
  .put(validateIncome, updateIncome)
  .delete(deleteIncome);

module.exports = router;
