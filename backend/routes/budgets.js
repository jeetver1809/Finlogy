const express = require('express');
const {
  getBudgets,
  getBudget,
  createBudget,
  updateBudget,
  deleteBudget,
  getBudgetAlerts,
} = require('../controllers/budgetController');
const { protect } = require('../middleware/auth');
const { validateBudget } = require('../middleware/validation');

const router = express.Router();

// All routes are protected
router.use(protect);

router.route('/')
  .get(getBudgets)
  .post(validateBudget, createBudget);

router.get('/alerts', getBudgetAlerts);

router.route('/:id')
  .get(getBudget)
  .put(validateBudget, updateBudget)
  .delete(deleteBudget);

module.exports = router;
