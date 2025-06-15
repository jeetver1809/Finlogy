/**
 * 🤖 AI ROUTES
 * 
 * API endpoints for AI-powered features in the Personal Finance Tracker
 * 
 * Endpoints:
 * - POST /api/ai/categorize - Auto-categorize transactions
 * - POST /api/ai/insights - Generate financial insights
 * - POST /api/ai/chat - AI chat assistant
 * - POST /api/ai/analyze-patterns - Analyze expense patterns
 */

const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const { protect } = require('../middleware/auth');
const geminiService = require('../services/geminiService');

// Import models for data access
const Expense = require('../models/Expense');
const Income = require('../models/Income');
const Budget = require('../models/Budget');

// All routes are protected
router.use(protect);

/**
 * 🏷️ AUTO-CATEGORIZE TRANSACTION
 * POST /api/ai/categorize
 * 
 * Automatically categorizes a transaction using AI
 */
router.post('/categorize', [
  body('description').notEmpty().withMessage('Description is required'),
  body('amount').isNumeric().withMessage('Amount must be a number')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { description, amount } = req.body;

    // Use Gemini AI to categorize the transaction
    const category = await geminiService.categorizeTransaction(description, amount);

    res.json({
      success: true,
      data: {
        category,
        description,
        amount,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('❌ AI categorization error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to categorize transaction',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

/**
 * 💡 GENERATE FINANCIAL INSIGHTS
 * POST /api/ai/insights
 * 
 * Generates personalized financial insights based on user data
 */
router.post('/insights', [
  body('period').optional().isIn(['week', 'month', 'year']).withMessage('Invalid period')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { period = 'month' } = req.body;
    const userId = req.user.id;

    // Calculate date range based on period
    const now = new Date();
    let startDate;
    
    switch (period) {
      case 'week':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case 'year':
        startDate = new Date(now.getFullYear(), 0, 1);
        break;
      case 'month':
      default:
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        break;
    }

    // Fetch user's financial data
    const [expenses, income, budgets] = await Promise.all([
      Expense.find({ 
        user: userId, 
        date: { $gte: startDate, $lte: now } 
      }).sort({ date: -1 }).limit(50),
      
      Income.find({ 
        user: userId, 
        date: { $gte: startDate, $lte: now } 
      }).sort({ date: -1 }).limit(20),
      
      Budget.find({ user: userId })
    ]);

    // Combine transactions for analysis
    const transactions = [
      ...expenses.map(e => ({
        description: e.description,
        amount: e.amount,
        category: e.category,
        date: e.date,
        type: 'expense'
      })),
      ...income.map(i => ({
        description: i.description,
        amount: i.amount,
        category: i.source,
        date: i.date,
        type: 'income'
      }))
    ];

    // Calculate budget spending
    const budgetsWithSpending = budgets.map(budget => {
      const spent = expenses
        .filter(expense => expense.category === budget.category)
        .reduce((sum, expense) => sum + expense.amount, 0);
      
      return {
        category: budget.category,
        amount: budget.amount,
        spent: spent,
        remaining: budget.amount - spent
      };
    });

    // Generate AI insights
    const insights = await geminiService.generateFinancialInsights({
      transactions,
      budgets: budgetsWithSpending,
      period
    });

    res.json({
      success: true,
      data: {
        insights,
        period,
        dataPoints: {
          transactionCount: transactions.length,
          expenseCount: expenses.length,
          incomeCount: income.length,
          budgetCount: budgets.length
        },
        generatedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('❌ AI insights error:', error);

    // Provide more specific error messages
    let errorMessage = 'Failed to generate insights';
    let statusCode = 500;

    if (error.message.includes('fetch failed')) {
      errorMessage = 'Network connectivity issue. AI insights temporarily unavailable.';
      statusCode = 503; // Service Unavailable
    } else if (error.message.includes('timeout')) {
      errorMessage = 'AI service timeout. Please try again.';
      statusCode = 408; // Request Timeout
    } else if (error.message.includes('API key')) {
      errorMessage = 'AI service configuration issue.';
      statusCode = 503;
    }

    res.status(statusCode).json({
      success: false,
      message: errorMessage,
      error: process.env.NODE_ENV === 'development' ? error.message : 'Service temporarily unavailable',
      fallbackAvailable: true
    });
  }
});

/**
 * 💬 AI CHAT ASSISTANT
 * POST /api/ai/chat
 * 
 * Handles conversational queries about personal finance
 */
router.post('/chat', [
  body('message').notEmpty().withMessage('Message is required').isLength({ max: 500 }).withMessage('Message too long')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { message } = req.body;
    const userId = req.user.id;

    // Get recent financial context for the user
    const [recentExpenses, recentIncome, budgets] = await Promise.all([
      Expense.find({ user: userId })
        .sort({ date: -1 })
        .limit(10)
        .select('description amount category date'),
      
      Income.find({ user: userId })
        .sort({ date: -1 })
        .limit(5)
        .select('description amount source date'),
      
      Budget.find({ user: userId })
        .select('category amount')
    ]);

    // Calculate total balance
    const totalIncome = recentIncome.reduce((sum, income) => sum + income.amount, 0);
    const totalExpenses = recentExpenses.reduce((sum, expense) => sum + expense.amount, 0);
    const totalBalance = totalIncome - totalExpenses;

    // Prepare context for AI
    const context = {
      recentTransactions: [
        ...recentExpenses.map(e => ({
          description: e.description,
          amount: e.amount,
          category: e.category,
          type: 'expense'
        })),
        ...recentIncome.map(i => ({
          description: i.description,
          amount: i.amount,
          category: i.source,
          type: 'income'
        }))
      ],
      budgets: budgets.map(b => ({
        category: b.category,
        amount: b.amount
      })),
      totalBalance
    };

    // Get AI response
    const aiResponse = await geminiService.chatWithAI(message, context);

    res.json({
      success: true,
      data: {
        message: aiResponse,
        userMessage: message,
        timestamp: new Date().toISOString(),
        contextUsed: {
          transactionCount: context.recentTransactions.length,
          budgetCount: context.budgets.length,
          hasBalance: totalBalance !== 0
        }
      }
    });

  } catch (error) {
    console.error('❌ AI chat error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process chat message',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

/**
 * 📈 ANALYZE EXPENSE PATTERNS
 * POST /api/ai/analyze-patterns
 * 
 * Analyzes spending patterns and provides recommendations
 */
router.post('/analyze-patterns', [
  body('period').optional().isIn(['week', 'month', 'quarter', 'year']).withMessage('Invalid period')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { period = 'month' } = req.body;
    const userId = req.user.id;

    // Calculate date range
    const now = new Date();
    let startDate;
    
    switch (period) {
      case 'week':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case 'quarter':
        startDate = new Date(now.getFullYear(), Math.floor(now.getMonth() / 3) * 3, 1);
        break;
      case 'year':
        startDate = new Date(now.getFullYear(), 0, 1);
        break;
      case 'month':
      default:
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        break;
    }

    // Fetch expenses for the period
    const expenses = await Expense.find({
      user: userId,
      date: { $gte: startDate, $lte: now }
    }).sort({ date: -1 });

    if (expenses.length === 0) {
      return res.json({
        success: true,
        data: {
          patterns: ['No expenses found for the selected period'],
          recommendations: ['Start tracking your expenses to get personalized insights'],
          anomalies: [],
          period,
          expenseCount: 0
        }
      });
    }

    // Analyze patterns using AI
    const analysis = await geminiService.analyzeExpensePatterns(expenses);

    res.json({
      success: true,
      data: {
        ...analysis,
        period,
        expenseCount: expenses.length,
        totalAmount: expenses.reduce((sum, e) => sum + e.amount, 0),
        analyzedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('❌ AI pattern analysis error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to analyze patterns',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

/**
 * 🔍 AI SERVICE STATUS
 * GET /api/ai/status
 * 
 * Check if AI services are available
 */
router.get('/status', async (req, res) => {
  try {
    const isAvailable = geminiService.isAvailable();
    
    res.json({
      success: true,
      data: {
        aiAvailable: isAvailable,
        service: 'Gemini AI',
        features: {
          categorization: isAvailable,
          insights: isAvailable,
          chat: isAvailable,
          patternAnalysis: isAvailable
        },
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('❌ AI status check error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check AI status'
    });
  }
});

module.exports = router;
