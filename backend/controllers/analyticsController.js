const Expense = require('../models/Expense');
const Income = require('../models/Income');
const Budget = require('../models/Budget');
const mongoose = require('mongoose');

// @desc    Get financial summary
// @route   GET /api/analytics/summary
// @access  Private
const getSummary = async (req, res) => {
  try {
    const { period = 'month' } = req.query;
    const userId = req.user.id;

    // Calculate date range based on period
    const now = new Date();
    let startDate, endDate;

    switch (period) {
      case 'week':
        startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 7);
        endDate = now;
        break;
      case 'month':
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0);
        break;
      case 'year':
        startDate = new Date(now.getFullYear(), 0, 1);
        endDate = new Date(now.getFullYear(), 11, 31);
        break;
      default:
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    }

    // Get total expenses
    const expenseResult = await Expense.getTotalExpenses(userId, startDate, endDate);
    const totalExpenses = expenseResult.length > 0 ? expenseResult[0].total : 0;
    const expenseCount = expenseResult.length > 0 ? expenseResult[0].count : 0;

    // Get total income
    const incomeResult = await Income.getTotalIncome(userId, startDate, endDate);
    const totalIncome = incomeResult.length > 0 ? incomeResult[0].total : 0;
    const incomeCount = incomeResult.length > 0 ? incomeResult[0].count : 0;

    // Calculate net income
    const netIncome = totalIncome - totalExpenses;

    // Get expense breakdown by category
    const categoryBreakdown = await Expense.aggregate([
      {
        $match: {
          user: new mongoose.Types.ObjectId(userId),
          date: { $gte: startDate, $lte: endDate },
        },
      },
      {
        $group: {
          _id: '$category',
          total: { $sum: '$amount' },
          count: { $sum: 1 },
        },
      },
      {
        $sort: { total: -1 },
      },
    ]);

    // Get recent transactions
    const recentExpenses = await Expense.find({
      user: userId,
      date: { $gte: startDate, $lte: endDate },
    })
      .sort({ date: -1 })
      .limit(5)
      .select('title amount category date');

    const recentIncome = await Income.find({
      user: userId,
      date: { $gte: startDate, $lte: endDate },
    })
      .sort({ date: -1 })
      .limit(5)
      .select('title amount source date');

    res.json({
      success: true,
      data: {
        period,
        dateRange: { startDate, endDate },
        summary: {
          totalIncome,
          totalExpenses,
          netIncome,
          incomeCount,
          expenseCount,
        },
        categoryBreakdown,
        recentTransactions: {
          expenses: recentExpenses,
          income: recentIncome,
        },
      },
    });
  } catch (error) {
    console.error('Get summary error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while fetching summary',
    });
  }
};

// @desc    Get monthly analysis
// @route   GET /api/analytics/monthly
// @access  Private
const getMonthlyAnalysis = async (req, res) => {
  try {
    const { year = new Date().getFullYear() } = req.query;
    const userId = req.user.id;

    // Get monthly expenses
    const monthlyExpenses = await Expense.aggregate([
      {
        $match: {
          user: new mongoose.Types.ObjectId(userId),
          date: {
            $gte: new Date(year, 0, 1),
            $lte: new Date(year, 11, 31),
          },
        },
      },
      {
        $group: {
          _id: { $month: '$date' },
          total: { $sum: '$amount' },
          count: { $sum: 1 },
        },
      },
      {
        $sort: { _id: 1 },
      },
    ]);

    // Get monthly income
    const monthlyIncome = await Income.aggregate([
      {
        $match: {
          user: new mongoose.Types.ObjectId(userId),
          date: {
            $gte: new Date(year, 0, 1),
            $lte: new Date(year, 11, 31),
          },
        },
      },
      {
        $group: {
          _id: { $month: '$date' },
          total: { $sum: '$amount' },
          count: { $sum: 1 },
        },
      },
      {
        $sort: { _id: 1 },
      },
    ]);

    // Format data for charts
    const months = [
      'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
      'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
    ];

    const expenseData = new Array(12).fill(0);
    const incomeData = new Array(12).fill(0);

    monthlyExpenses.forEach(item => {
      expenseData[item._id - 1] = item.total;
    });

    monthlyIncome.forEach(item => {
      incomeData[item._id - 1] = item.total;
    });

    res.json({
      success: true,
      data: {
        year: parseInt(year),
        months,
        expenses: expenseData,
        income: incomeData,
        net: incomeData.map((income, index) => income - expenseData[index]),
      },
    });
  } catch (error) {
    console.error('Get monthly analysis error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while fetching monthly analysis',
    });
  }
};

// @desc    Get category analysis
// @route   GET /api/analytics/category
// @access  Private
const getCategoryAnalysis = async (req, res) => {
  try {
    const { period = 'month' } = req.query;
    const userId = req.user.id;

    // Calculate date range
    const now = new Date();
    let startDate, endDate;

    switch (period) {
      case 'week':
        startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 7);
        endDate = now;
        break;
      case 'month':
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0);
        break;
      case 'year':
        startDate = new Date(now.getFullYear(), 0, 1);
        endDate = new Date(now.getFullYear(), 11, 31);
        break;
      default:
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    }

    // Get category breakdown with trends
    const categoryAnalysis = await Expense.aggregate([
      {
        $match: {
          user: new mongoose.Types.ObjectId(userId),
          date: { $gte: startDate, $lte: endDate },
        },
      },
      {
        $group: {
          _id: '$category',
          total: { $sum: '$amount' },
          count: { $sum: 1 },
          avgAmount: { $avg: '$amount' },
          maxAmount: { $max: '$amount' },
          minAmount: { $min: '$amount' },
        },
      },
      {
        $sort: { total: -1 },
      },
    ]);

    // Calculate total for percentages
    const totalExpenses = categoryAnalysis.reduce((sum, cat) => sum + cat.total, 0);

    // Add percentage to each category
    const categoriesWithPercentage = categoryAnalysis.map(cat => ({
      ...cat,
      percentage: totalExpenses > 0 ? (cat.total / totalExpenses) * 100 : 0,
    }));

    res.json({
      success: true,
      data: {
        period,
        dateRange: { startDate, endDate },
        totalExpenses,
        categories: categoriesWithPercentage,
      },
    });
  } catch (error) {
    console.error('Get category analysis error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while fetching category analysis',
    });
  }
};

module.exports = {
  getSummary,
  getMonthlyAnalysis,
  getCategoryAnalysis,
};
