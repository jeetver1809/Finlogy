/**
 * 🤖 GEMINI AI SERVICE
 * 
 * This service handles all interactions with Google's Gemini AI API
 * for the Personal Finance Tracker application.
 * 
 * Features:
 * - Transaction categorization
 * - Financial insights generation
 * - Chat assistant functionality
 * - Expense pattern analysis
 */

const { GoogleGenerativeAI } = require('@google/generative-ai');

class GeminiService {
  constructor() {
    // Initialize Gemini AI with API key
    if (!process.env.GEMINI_API_KEY) {
      console.warn('⚠️ GEMINI_API_KEY not found in environment variables');
      this.genAI = null;
      this.model = null;
      return;
    }

    try {
      this.genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
      // Use Gemini 1.5 Flash for faster responses and better efficiency
      this.model = this.genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
      console.log('✅ Gemini AI service initialized successfully');
    } catch (error) {
      console.error('❌ Failed to initialize Gemini AI:', error);
      this.genAI = null;
      this.model = null;
    }
  }

  /**
   * Check if the service is properly initialized
   */
  isAvailable() {
    return this.model !== null;
  }

  /**
   * 🏷️ TRANSACTION CATEGORIZATION
   * 
   * Automatically categorizes transactions based on description and amount
   * 
   * @param {string} description - Transaction description
   * @param {number} amount - Transaction amount
   * @returns {Promise<string>} - Category name
   */
  async categorizeTransaction(description, amount) {
    if (!this.isAvailable()) {
      console.warn('Gemini AI not available, using fallback categorization');
      return this.fallbackCategorization(description);
    }

    const prompt = `
Categorize this financial transaction for a personal finance tracker:

Description: "${description}"
Amount: ₹${amount}

Available categories:
- Food & Dining
- Transportation
- Entertainment
- Shopping
- Bills & Utilities
- Healthcare
- Education
- Investment
- Salary
- Freelance
- Business
- Travel
- Groceries
- Other

Rules:
1. Return ONLY the category name (exactly as listed above)
2. Choose the most specific and appropriate category
3. If uncertain, use "Other"
4. Consider Indian context (₹ currency, local businesses)

Category:`;

    try {
      const result = await this.model.generateContent(prompt);
      const response = await result.response;
      const category = response.text().trim();
      
      // Validate the response is one of our categories
      const validCategories = [
        'Food & Dining', 'Transportation', 'Entertainment', 'Shopping',
        'Bills & Utilities', 'Healthcare', 'Education', 'Investment',
        'Salary', 'Freelance', 'Business', 'Travel', 'Groceries', 'Other'
      ];
      
      if (validCategories.includes(category)) {
        return category;
      } else {
        console.warn(`Invalid category returned: ${category}, using fallback`);
        return this.fallbackCategorization(description);
      }
    } catch (error) {
      console.error('❌ Gemini categorization error:', error);
      return this.fallbackCategorization(description);
    }
  }

  /**
   * 💡 FINANCIAL INSIGHTS GENERATION
   *
   * Generates personalized financial insights based on user data
   *
   * @param {Object} financialData - User's financial data
   * @returns {Promise<string>} - Generated insights
   */
  async generateFinancialInsights(financialData) {
    if (!this.isAvailable()) {
      return 'AI insights are currently unavailable. Please check your API configuration.';
    }

    const { transactions, budgets, period = 'month' } = financialData;

    // Check network connectivity first
    try {
      // Test basic connectivity to Google's servers
      const testResponse = await fetch('https://www.google.com', {
        method: 'HEAD',
        timeout: 5000
      });
      console.log('✅ Network connectivity test passed');
    } catch (networkError) {
      console.error('❌ Network connectivity test failed:', networkError.message);
      return this.generateFallbackInsights(financialData);
    }

    const prompt = `
Analyze this personal finance data and provide helpful insights:

RECENT TRANSACTIONS (last 10):
${transactions.slice(0, 10).map(t => 
  `- ${t.description}: ₹${t.amount} (${t.category || 'Uncategorized'}) on ${new Date(t.date).toLocaleDateString()}`
).join('\n')}

CURRENT BUDGETS:
${budgets.map(b => 
  `- ${b.category}: ₹${b.amount} budget, ₹${b.spent || 0} spent`
).join('\n')}

ANALYSIS PERIOD: ${period}

Please provide:
1. 📊 Spending pattern analysis (2-3 sentences)
2. 🎯 Budget performance summary (2-3 sentences)
3. 💡 3 specific, actionable recommendations

Keep the response:
- Under 250 words
- Friendly and encouraging tone
- Focused on actionable advice
- Use Indian currency context (₹)
- Include relevant emojis for better readability

Response:`;

    try {
      // Add timeout and retry logic
      const result = await Promise.race([
        this.model.generateContent(prompt),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('API request timeout')), 15000)
        )
      ]);

      const response = await result.response;
      const insights = response.text().trim();

      console.log('✅ Generated AI insights successfully');
      return insights;

    } catch (error) {
      console.error('❌ Gemini insights error:', error);

      // Provide more specific error information
      if (error.message.includes('fetch failed')) {
        console.error('❌ Network connectivity issue detected');
      } else if (error.message.includes('timeout')) {
        console.error('❌ API request timeout');
      } else if (error.message.includes('API key')) {
        console.error('❌ API key issue');
      }

      // Return fallback insights based on the data
      return this.generateFallbackInsights(financialData);
    }
  }

  /**
   * 💬 AI CHAT ASSISTANT
   * 
   * Handles conversational queries about personal finance
   * 
   * @param {string} userMessage - User's message
   * @param {Object} context - User's financial context
   * @returns {Promise<string>} - AI response
   */
  async chatWithAI(userMessage, context = {}) {
    if (!this.isAvailable()) {
      return 'I apologize, but the AI assistant is currently unavailable. Please check your configuration.';
    }

    const { recentTransactions = [], budgets = [], totalBalance = 0 } = context;

    const prompt = `
You are a helpful personal finance assistant for an Indian user. You have access to their financial data and should provide helpful, accurate advice.

USER'S FINANCIAL CONTEXT:
- Current Balance: ₹${totalBalance}
- Recent Transactions: ${recentTransactions.length} transactions
- Active Budgets: ${budgets.length} budgets

RECENT ACTIVITY:
${recentTransactions.slice(0, 5).map(t => 
  `- ${t.description}: ₹${t.amount} (${t.category || 'Uncategorized'})`
).join('\n')}

USER ASKS: "${userMessage}"

Guidelines:
1. Be conversational, helpful, and encouraging
2. Provide specific, actionable advice
3. Use Indian currency (₹) and context
4. If you need more information, ask specific questions
5. Keep responses under 150 words
6. Use emojis appropriately for better engagement
7. Focus on practical financial advice

Response:`;

    try {
      const result = await this.model.generateContent(prompt);
      const response = await result.response;
      return response.text().trim();
    } catch (error) {
      console.error('❌ Gemini chat error:', error);
      return 'I apologize, but I\'m having trouble processing your request right now. Please try again in a moment. 🤖';
    }
  }

  /**
   * 📈 EXPENSE PATTERN ANALYSIS
   * 
   * Analyzes spending patterns and provides recommendations
   * 
   * @param {Array} expenses - Array of expense transactions
   * @returns {Promise<Object>} - Analysis results
   */
  async analyzeExpensePatterns(expenses) {
    if (!this.isAvailable()) {
      return {
        patterns: [],
        recommendations: ['AI analysis is currently unavailable.'],
        anomalies: []
      };
    }

    // Group expenses by category and calculate totals
    const categoryTotals = expenses.reduce((acc, expense) => {
      const category = expense.category || 'Other';
      acc[category] = (acc[category] || 0) + expense.amount;
      return acc;
    }, {});

    const prompt = `
Analyze these expense patterns for personal finance insights:

EXPENSE BREAKDOWN:
${Object.entries(categoryTotals).map(([category, amount]) => 
  `- ${category}: ₹${amount}`
).join('\n')}

TOTAL EXPENSES: ₹${expenses.reduce((sum, e) => sum + e.amount, 0)}
NUMBER OF TRANSACTIONS: ${expenses.length}

Provide analysis in this JSON format:
{
  "patterns": ["pattern1", "pattern2", "pattern3"],
  "recommendations": ["recommendation1", "recommendation2", "recommendation3"],
  "anomalies": ["anomaly1", "anomaly2"]
}

Focus on:
1. Spending patterns and trends
2. Actionable recommendations for improvement
3. Any unusual spending that stands out
4. Use Indian financial context

Return only valid JSON:`;

    try {
      const result = await this.model.generateContent(prompt);
      const response = await result.response;
      const jsonText = response.text().trim();
      
      // Try to parse JSON response
      try {
        return JSON.parse(jsonText);
      } catch (parseError) {
        console.warn('Failed to parse JSON response, returning fallback');
        return {
          patterns: ['Unable to analyze patterns at the moment'],
          recommendations: ['Please try again later'],
          anomalies: []
        };
      }
    } catch (error) {
      console.error('❌ Gemini pattern analysis error:', error);
      return {
        patterns: ['Analysis temporarily unavailable'],
        recommendations: ['Please check back later'],
        anomalies: []
      };
    }
  }

  /**
   * 💡 FALLBACK INSIGHTS GENERATION
   *
   * Generates basic insights when AI is unavailable
   *
   * @param {Object} financialData - User's financial data
   * @returns {string} - Generated fallback insights
   */
  generateFallbackInsights(financialData) {
    const { transactions = [], budgets = [], period = 'month' } = financialData;

    // Calculate basic statistics
    const expenses = transactions.filter(t => t.type === 'expense');
    const income = transactions.filter(t => t.type === 'income');
    const totalExpenses = expenses.reduce((sum, t) => sum + t.amount, 0);
    const totalIncome = income.reduce((sum, t) => sum + t.amount, 0);

    // Category breakdown
    const categoryTotals = expenses.reduce((acc, expense) => {
      const category = expense.category || 'Other';
      acc[category] = (acc[category] || 0) + expense.amount;
      return acc;
    }, {});

    const topCategory = Object.entries(categoryTotals)
      .sort(([,a], [,b]) => b - a)[0];

    // Budget analysis
    const budgetAnalysis = budgets.length > 0
      ? `You have ${budgets.length} active budgets set up.`
      : 'Consider setting up budgets to better track your spending.';

    // Generate insights in paragraph format
    const insights = `
📊 Spending Analysis (${period})

Your financial activity shows total expenses of ₹${totalExpenses.toLocaleString('en-IN')} against income of ₹${totalIncome.toLocaleString('en-IN')}, resulting in net savings of ₹${(totalIncome - totalExpenses).toLocaleString('en-IN')}. ${totalIncome > totalExpenses ? 'You\'re maintaining a positive savings rate, which is excellent for your financial health.' : 'Consider reviewing your expenses to improve your savings rate.'}

🎯 Budget Overview

${budgetAnalysis} ${topCategory ? `Your highest spending category is ${topCategory[0]} with ₹${topCategory[1].toLocaleString('en-IN')} spent, which represents a significant portion of your expenses.` : 'Tracking your spending by category will help you identify areas for potential savings.'}

💡 Financial Recommendations

Based on your current financial patterns, focus on tracking your daily expenses to identify spending trends and opportunities for optimization. Setting up budgets for major expense categories will provide better control over your finances. Regular weekly reviews of your transactions will help you stay aligned with your financial goals, and consider automating your savings to build wealth consistently over time.

*Note: AI insights are temporarily unavailable. These are basic analytics based on your data.*
    `.trim();

    return insights;
  }

  /**
   * 🔄 FALLBACK CATEGORIZATION
   *
   * Simple rule-based categorization when AI is unavailable
   *
   * @param {string} description - Transaction description
   * @returns {string} - Category name
   */
  fallbackCategorization(description) {
    const desc = description.toLowerCase();
    
    // Simple keyword-based categorization
    if (desc.includes('food') || desc.includes('restaurant') || desc.includes('cafe') || desc.includes('zomato') || desc.includes('swiggy')) {
      return 'Food & Dining';
    }
    if (desc.includes('uber') || desc.includes('ola') || desc.includes('petrol') || desc.includes('fuel') || desc.includes('bus') || desc.includes('metro')) {
      return 'Transportation';
    }
    if (desc.includes('movie') || desc.includes('netflix') || desc.includes('spotify') || desc.includes('game')) {
      return 'Entertainment';
    }
    if (desc.includes('amazon') || desc.includes('flipkart') || desc.includes('shopping') || desc.includes('mall')) {
      return 'Shopping';
    }
    if (desc.includes('electricity') || desc.includes('water') || desc.includes('gas') || desc.includes('internet') || desc.includes('mobile')) {
      return 'Bills & Utilities';
    }
    if (desc.includes('salary') || desc.includes('payroll')) {
      return 'Salary';
    }
    if (desc.includes('grocery') || desc.includes('supermarket') || desc.includes('vegetables')) {
      return 'Groceries';
    }
    
    return 'Other';
  }
}

// Export singleton instance
module.exports = new GeminiService();
