const Budget = require('../models/Budget');

// @desc    Get all budgets for user
// @route   GET /api/budgets
// @access  Private
const getBudgets = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      category,
      period,
      isActive,
      sortBy = 'createdAt',
      sortOrder = 'desc',
    } = req.query;

    // Build query
    const query = { user: req.user.id };

    if (category) {
      query.category = category;
    }

    if (period) {
      query.period = period;
    }

    if (isActive !== undefined) {
      query.isActive = isActive === 'true';
    }

    // Build sort object
    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    // Execute query with pagination
    const budgets = await Budget.find(query)
      .sort(sort)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();

    // Update spent amounts for all budgets
    for (const budget of budgets) {
      await budget.updateSpent();
    }

    // Get total count for pagination
    const total = await Budget.countDocuments(query);

    res.json({
      success: true,
      data: budgets,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error('Get budgets error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while fetching budgets',
    });
  }
};

// @desc    Get single budget
// @route   GET /api/budgets/:id
// @access  Private
const getBudget = async (req, res) => {
  try {
    const budget = await Budget.findOne({
      _id: req.params.id,
      user: req.user.id,
    });

    if (!budget) {
      return res.status(404).json({
        success: false,
        message: 'Budget not found',
      });
    }

    // Update spent amount
    await budget.updateSpent();

    res.json({
      success: true,
      data: budget,
    });
  } catch (error) {
    console.error('Get budget error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while fetching budget',
    });
  }
};

// @desc    Create new budget
// @route   POST /api/budgets
// @access  Private
const createBudget = async (req, res) => {
  try {
    // Check if budget already exists for this category and period
    const existingBudget = await Budget.findOne({
      user: req.user.id,
      category: req.body.category,
      period: req.body.period,
      isActive: true,
      endDate: { $gte: new Date() },
    });

    if (existingBudget) {
      return res.status(400).json({
        success: false,
        message: `Active budget already exists for ${req.body.category} category with ${req.body.period} period`,
      });
    }

    const budgetData = {
      ...req.body,
      user: req.user.id,
    };

    const budget = await Budget.create(budgetData);

    // Update spent amount
    await budget.updateSpent();

    res.status(201).json({
      success: true,
      message: 'Budget created successfully',
      data: budget,
    });
  } catch (error) {
    console.error('Create budget error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while creating budget',
    });
  }
};

// @desc    Update budget
// @route   PUT /api/budgets/:id
// @access  Private
const updateBudget = async (req, res) => {
  try {
    let budget = await Budget.findOne({
      _id: req.params.id,
      user: req.user.id,
    });

    if (!budget) {
      return res.status(404).json({
        success: false,
        message: 'Budget not found',
      });
    }

    budget = await Budget.findByIdAndUpdate(
      req.params.id,
      req.body,
      {
        new: true,
        runValidators: true,
      }
    );

    // Update spent amount
    await budget.updateSpent();

    res.json({
      success: true,
      message: 'Budget updated successfully',
      data: budget,
    });
  } catch (error) {
    console.error('Update budget error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while updating budget',
    });
  }
};

// @desc    Delete budget
// @route   DELETE /api/budgets/:id
// @access  Private
const deleteBudget = async (req, res) => {
  try {
    const budget = await Budget.findOne({
      _id: req.params.id,
      user: req.user.id,
    });

    if (!budget) {
      return res.status(404).json({
        success: false,
        message: 'Budget not found',
      });
    }

    await budget.deleteOne();

    res.json({
      success: true,
      message: 'Budget deleted successfully',
    });
  } catch (error) {
    console.error('Delete budget error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while deleting budget',
    });
  }
};

// @desc    Get budget alerts
// @route   GET /api/budgets/alerts
// @access  Private
const getBudgetAlerts = async (req, res) => {
  try {
    const budgets = await Budget.find({
      user: req.user.id,
      isActive: true,
      endDate: { $gte: new Date() },
    });

    const alerts = [];

    for (const budget of budgets) {
      await budget.updateSpent();
      
      const percentage = budget.percentageSpent;
      
      if (percentage >= budget.alertThreshold) {
        alerts.push({
          budgetId: budget._id,
          budgetName: budget.name,
          category: budget.category,
          percentage: Math.round(percentage),
          amount: budget.amount,
          spent: budget.spent,
          remaining: budget.remaining,
          status: budget.status,
          alertThreshold: budget.alertThreshold,
        });
      }
    }

    res.json({
      success: true,
      data: alerts,
    });
  } catch (error) {
    console.error('Get budget alerts error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while fetching budget alerts',
    });
  }
};

module.exports = {
  getBudgets,
  getBudget,
  createBudget,
  updateBudget,
  deleteBudget,
  getBudgetAlerts,
};
