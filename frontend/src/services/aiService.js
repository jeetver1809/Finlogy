/**
 * 🤖 AI SERVICE (Frontend)
 * 
 * Frontend service for communicating with AI endpoints
 * Handles all AI-related API calls from the React components
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5001/api';

class AiService {
  constructor() {
    this.baseURL = `${API_BASE_URL}/ai`;
  }

  /**
   * Get authentication headers
   */
  getAuthHeaders() {
    const token = localStorage.getItem('token');
    return {
      'Content-Type': 'application/json',
      'Authorization': token ? `Bearer ${token}` : ''
    };
  }

  /**
   * Handle API responses
   */
  async handleResponse(response) {
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
    }
    return await response.json();
  }

  /**
   * 🏷️ AUTO-CATEGORIZE TRANSACTION
   * 
   * @param {string} description - Transaction description
   * @param {number} amount - Transaction amount
   * @returns {Promise<string>} - Category name
   */
  async categorizeTransaction(description, amount) {
    try {
      const response = await fetch(`${this.baseURL}/categorize`, {
        method: 'POST',
        headers: this.getAuthHeaders(),
        body: JSON.stringify({ description, amount })
      });

      const result = await this.handleResponse(response);
      return result.data.category;
    } catch (error) {
      console.error('❌ AI categorization error:', error);
      // Return fallback category
      return 'Other';
    }
  }

  /**
   * 💡 GENERATE FINANCIAL INSIGHTS
   *
   * @param {string} period - Analysis period (week, month, year)
   * @returns {Promise<string>} - Generated insights
   */
  async generateInsights(period = 'month') {
    try {
      const response = await fetch(`${this.baseURL}/insights`, {
        method: 'POST',
        headers: this.getAuthHeaders(),
        body: JSON.stringify({ period }),
        // Add timeout
        signal: AbortSignal.timeout(20000) // 20 second timeout
      });

      const result = await this.handleResponse(response);
      return result.data.insights;
    } catch (error) {
      console.error('❌ AI insights error:', error);

      // Provide more specific error messages
      if (error.name === 'AbortError') {
        throw new Error('Request timeout. AI service is taking too long to respond.');
      } else if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
        throw new Error('Network connectivity issue. AI insights temporarily unavailable.');
      } else if (error.message.includes('503') || error.message.includes('Service Unavailable')) {
        throw new Error('AI service temporarily unavailable. Showing basic analytics instead.');
      } else {
        throw new Error('Failed to generate insights. Please try again.');
      }
    }
  }

  /**
   * 💬 AI CHAT ASSISTANT
   * 
   * @param {string} message - User's message
   * @returns {Promise<string>} - AI response
   */
  async chatWithAI(message) {
    try {
      const response = await fetch(`${this.baseURL}/chat`, {
        method: 'POST',
        headers: this.getAuthHeaders(),
        body: JSON.stringify({ message })
      });

      const result = await this.handleResponse(response);
      return result.data.message;
    } catch (error) {
      console.error('❌ AI chat error:', error);
      throw new Error('Sorry, I\'m having trouble responding right now. Please try again.');
    }
  }

  /**
   * 📈 ANALYZE EXPENSE PATTERNS
   * 
   * @param {string} period - Analysis period
   * @returns {Promise<Object>} - Pattern analysis results
   */
  async analyzePatterns(period = 'month') {
    try {
      const response = await fetch(`${this.baseURL}/analyze-patterns`, {
        method: 'POST',
        headers: this.getAuthHeaders(),
        body: JSON.stringify({ period })
      });

      const result = await this.handleResponse(response);
      return result.data;
    } catch (error) {
      console.error('❌ AI pattern analysis error:', error);
      throw new Error('Failed to analyze patterns. Please try again.');
    }
  }

  /**
   * 🔍 CHECK AI SERVICE STATUS
   * 
   * @returns {Promise<Object>} - Service status
   */
  async getStatus() {
    try {
      const response = await fetch(`${this.baseURL}/status`, {
        method: 'GET',
        headers: this.getAuthHeaders()
      });

      const result = await this.handleResponse(response);
      return result.data;
    } catch (error) {
      console.error('❌ AI status check error:', error);
      return {
        aiAvailable: false,
        service: 'Unknown',
        features: {
          categorization: false,
          insights: false,
          chat: false,
          patternAnalysis: false
        }
      };
    }
  }

  /**
   * 🎯 SMART EXPENSE SUGGESTIONS
   * 
   * Get AI suggestions for expense entry based on description
   * 
   * @param {string} description - Partial description
   * @returns {Promise<Object>} - Suggestions object
   */
  async getExpenseSuggestions(description) {
    if (!description || description.length < 3) {
      return {
        category: 'Other',
        suggestedAmount: null,
        confidence: 0
      };
    }

    try {
      // Use categorization as a base for suggestions
      const category = await this.categorizeTransaction(description, 0);
      
      return {
        category,
        suggestedAmount: null, // Could be enhanced with historical data
        confidence: 0.8
      };
    } catch (error) {
      console.error('❌ AI suggestions error:', error);
      return {
        category: 'Other',
        suggestedAmount: null,
        confidence: 0
      };
    }
  }

  /**
   * 📊 BATCH CATEGORIZE TRANSACTIONS
   * 
   * Categorize multiple transactions at once
   * 
   * @param {Array} transactions - Array of {description, amount} objects
   * @returns {Promise<Array>} - Array of categories
   */
  async batchCategorize(transactions) {
    try {
      // For now, process one by one (could be optimized with batch endpoint)
      const categories = await Promise.all(
        transactions.map(async (transaction) => {
          try {
            return await this.categorizeTransaction(transaction.description, transaction.amount);
          } catch (error) {
            console.warn(`Failed to categorize: ${transaction.description}`);
            return 'Other';
          }
        })
      );

      return categories;
    } catch (error) {
      console.error('❌ Batch categorization error:', error);
      // Return fallback categories
      return transactions.map(() => 'Other');
    }
  }

  /**
   * 🎨 FORMAT AI RESPONSE
   * 
   * Format AI responses for better display
   * 
   * @param {string} response - Raw AI response
   * @returns {string} - Formatted response
   */
  formatResponse(response) {
    if (!response) return '';

    // Add line breaks for better readability
    return response
      .replace(/\n/g, '<br>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') // Bold text
      .replace(/\*(.*?)\*/g, '<em>$1</em>') // Italic text
      .trim();
  }

  /**
   * 🔄 RETRY MECHANISM
   * 
   * Retry failed requests with exponential backoff
   * 
   * @param {Function} apiCall - The API call function
   * @param {number} maxRetries - Maximum number of retries
   * @returns {Promise} - Result of the API call
   */
  async retryRequest(apiCall, maxRetries = 3) {
    let lastError;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await apiCall();
      } catch (error) {
        lastError = error;
        
        if (attempt === maxRetries) {
          throw lastError;
        }
        
        // Exponential backoff: wait 1s, 2s, 4s...
        const delay = Math.pow(2, attempt - 1) * 1000;
        await new Promise(resolve => setTimeout(resolve, delay));
        
        console.warn(`AI request attempt ${attempt} failed, retrying in ${delay}ms...`);
      }
    }
    
    throw lastError;
  }

  /**
   * 🎯 SMART BUDGET RECOMMENDATIONS
   * 
   * Get AI-powered budget recommendations
   * 
   * @param {Object} financialData - User's financial data
   * @returns {Promise<Object>} - Budget recommendations
   */
  async getBudgetRecommendations(financialData) {
    try {
      // This could be a separate endpoint, for now use insights
      const insights = await this.generateInsights('month');
      
      // Extract budget-related recommendations from insights
      const budgetRegex = /budget|spend|save|allocate/i;
      const budgetInsights = insights.split('\n').filter(line => budgetRegex.test(line));
      
      return {
        recommendations: budgetInsights,
        confidence: 0.7,
        source: 'ai_insights'
      };
    } catch (error) {
      console.error('❌ Budget recommendations error:', error);
      return {
        recommendations: ['Unable to generate budget recommendations at this time.'],
        confidence: 0,
        source: 'fallback'
      };
    }
  }
}

// Export singleton instance
export const aiService = new AiService();
export default aiService;
