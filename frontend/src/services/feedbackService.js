/**
 * 📝 FEEDBACK SERVICE (Frontend)
 * 
 * Frontend service for handling feedback-related API calls
 * Manages feedback submission, retrieval, and statistics
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5001/api';

class FeedbackService {
  constructor() {
    this.baseURL = `${API_BASE_URL}/feedback`;
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
   * 📝 SUBMIT FEEDBACK
   * 
   * @param {Object} feedbackData - Feedback data
   * @param {number} feedbackData.rating - Rating (1-5)
   * @param {string} feedbackData.feedback - Feedback text
   * @param {string} feedbackData.category - Feedback category
   * @param {string} feedbackData.email - Optional email
   * @returns {Promise<Object>} - Submission result
   */
  async submitFeedback(feedbackData) {
    try {
      const response = await fetch(this.baseURL, {
        method: 'POST',
        headers: this.getAuthHeaders(),
        body: JSON.stringify(feedbackData)
      });

      const result = await this.handleResponse(response);
      return result.data;
    } catch (error) {
      console.error('❌ Feedback submission error:', error);
      throw new Error(error.message || 'Failed to submit feedback. Please try again.');
    }
  }

  /**
   * 📊 GET FEEDBACK STATISTICS
   * 
   * @returns {Promise<Object>} - Feedback statistics
   */
  async getFeedbackStats() {
    try {
      const response = await fetch(`${this.baseURL}/stats`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      });

      const result = await this.handleResponse(response);
      return result.data;
    } catch (error) {
      console.error('❌ Feedback stats error:', error);
      throw new Error('Failed to fetch feedback statistics.');
    }
  }

  /**
   * 📋 GET USER'S FEEDBACK HISTORY
   * 
   * @param {number} page - Page number
   * @param {number} limit - Items per page
   * @returns {Promise<Object>} - User's feedback history
   */
  async getMyFeedback(page = 1, limit = 10) {
    try {
      const response = await fetch(`${this.baseURL}/my?page=${page}&limit=${limit}`, {
        method: 'GET',
        headers: this.getAuthHeaders()
      });

      const result = await this.handleResponse(response);
      return result.data;
    } catch (error) {
      console.error('❌ User feedback history error:', error);
      throw new Error('Failed to fetch feedback history.');
    }
  }

  /**
   * 👍 MARK FEEDBACK AS HELPFUL
   * 
   * @param {string} feedbackId - Feedback ID
   * @returns {Promise<Object>} - Updated helpful count
   */
  async markFeedbackHelpful(feedbackId) {
    try {
      const response = await fetch(`${this.baseURL}/${feedbackId}/helpful`, {
        method: 'PUT',
        headers: this.getAuthHeaders()
      });

      const result = await this.handleResponse(response);
      return result.data;
    } catch (error) {
      console.error('❌ Mark feedback helpful error:', error);
      throw new Error('Failed to mark feedback as helpful.');
    }
  }

  /**
   * 🌟 GET PUBLIC FEEDBACK
   * 
   * @param {number} limit - Number of feedback items to fetch
   * @param {number} minRating - Minimum rating filter
   * @returns {Promise<Array>} - Public feedback list
   */
  async getPublicFeedback(limit = 6, minRating = 4) {
    try {
      const response = await fetch(`${this.baseURL}/public?limit=${limit}&minRating=${minRating}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      });

      const result = await this.handleResponse(response);
      return result.data;
    } catch (error) {
      console.error('❌ Public feedback error:', error);
      throw new Error('Failed to fetch public feedback.');
    }
  }

  /**
   * 🔄 RETRY FAILED REQUEST
   * 
   * @param {Function} requestFunction - Function to retry
   * @param {number} maxRetries - Maximum retry attempts
   * @param {number} delay - Delay between retries (ms)
   * @returns {Promise<any>} - Request result
   */
  async retryRequest(requestFunction, maxRetries = 3, delay = 1000) {
    let lastError;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await requestFunction();
      } catch (error) {
        lastError = error;
        
        if (attempt === maxRetries) {
          break;
        }
        
        // Wait before retrying
        await new Promise(resolve => setTimeout(resolve, delay * attempt));
      }
    }
    
    throw lastError;
  }

  /**
   * 📈 GET FEEDBACK ANALYTICS
   * 
   * @returns {Promise<Object>} - Detailed feedback analytics
   */
  async getFeedbackAnalytics() {
    try {
      const stats = await this.getFeedbackStats();
      
      // Calculate additional metrics
      const totalFeedback = stats.overall.totalFeedback;
      const avgRating = stats.overall.averageRating;
      const distribution = stats.overall.ratingDistribution;
      
      // Calculate satisfaction rate (4-5 star ratings)
      const satisfiedCount = (distribution[4] || 0) + (distribution[5] || 0);
      const satisfactionRate = totalFeedback > 0 ? (satisfiedCount / totalFeedback) * 100 : 0;
      
      // Calculate most common rating
      const mostCommonRating = Object.entries(distribution)
        .reduce((a, b) => distribution[a[0]] > distribution[b[0]] ? a : b)[0];
      
      return {
        ...stats,
        analytics: {
          satisfactionRate: Math.round(satisfactionRate * 10) / 10,
          mostCommonRating: parseInt(mostCommonRating),
          totalResponses: totalFeedback,
          averageRating: avgRating
        }
      };
    } catch (error) {
      console.error('❌ Feedback analytics error:', error);
      throw new Error('Failed to fetch feedback analytics.');
    }
  }
}

// Create and export a singleton instance
export const feedbackService = new FeedbackService();
export default feedbackService;
