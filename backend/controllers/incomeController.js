const Income = require('../models/Income');

// @desc    Get all income for user
// @route   GET /api/income
// @access  Private
const getIncome = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      source,
      startDate,
      endDate,
      search,
      sortBy = 'date',
      sortOrder = 'desc',
    } = req.query;

    // Build query
    const query = { user: req.user.id };

    if (source) {
      query.source = source;
    }

    if (startDate && endDate) {
      query.date = {
        $gte: new Date(startDate),
        $lte: new Date(endDate),
      };
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
      ];
    }

    // Build sort object
    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    // Execute query with pagination
    const income = await Income.find(query)
      .sort(sort)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();

    // Get total count for pagination
    const total = await Income.countDocuments(query);

    res.json({
      success: true,
      data: income,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error('Get income error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while fetching income',
    });
  }
};

// @desc    Get single income entry
// @route   GET /api/income/:id
// @access  Private
const getIncomeEntry = async (req, res) => {
  try {
    const income = await Income.findOne({
      _id: req.params.id,
      user: req.user.id,
    });

    if (!income) {
      return res.status(404).json({
        success: false,
        message: 'Income entry not found',
      });
    }

    res.json({
      success: true,
      data: income,
    });
  } catch (error) {
    console.error('Get income entry error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while fetching income entry',
    });
  }
};

// @desc    Create new income entry
// @route   POST /api/income
// @access  Private
const createIncome = async (req, res) => {
  try {
    const incomeData = {
      ...req.body,
      user: req.user.id,
    };

    const income = await Income.create(incomeData);

    res.status(201).json({
      success: true,
      message: 'Income entry created successfully',
      data: income,
    });
  } catch (error) {
    console.error('Create income error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while creating income entry',
    });
  }
};

// @desc    Update income entry
// @route   PUT /api/income/:id
// @access  Private
const updateIncome = async (req, res) => {
  try {
    let income = await Income.findOne({
      _id: req.params.id,
      user: req.user.id,
    });

    if (!income) {
      return res.status(404).json({
        success: false,
        message: 'Income entry not found',
      });
    }

    income = await Income.findByIdAndUpdate(
      req.params.id,
      req.body,
      {
        new: true,
        runValidators: true,
      }
    );

    res.json({
      success: true,
      message: 'Income entry updated successfully',
      data: income,
    });
  } catch (error) {
    console.error('Update income error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while updating income entry',
    });
  }
};

// @desc    Delete income entry
// @route   DELETE /api/income/:id
// @access  Private
const deleteIncome = async (req, res) => {
  try {
    const income = await Income.findOne({
      _id: req.params.id,
      user: req.user.id,
    });

    if (!income) {
      return res.status(404).json({
        success: false,
        message: 'Income entry not found',
      });
    }

    await income.deleteOne();

    res.json({
      success: true,
      message: 'Income entry deleted successfully',
    });
  } catch (error) {
    console.error('Delete income error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while deleting income entry',
    });
  }
};

module.exports = {
  getIncome,
  getIncomeEntry,
  createIncome,
  updateIncome,
  deleteIncome,
};
