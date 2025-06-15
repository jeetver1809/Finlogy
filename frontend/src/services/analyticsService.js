import api from './api';

export const analyticsService = {
  // Get financial summary
  getSummary: async (period = 'month') => {
    const response = await api.get('/analytics/summary', {
      params: { period },
    });
    return response.data;
  },

  // Get monthly analysis
  getMonthlyAnalysis: async (year = new Date().getFullYear()) => {
    const response = await api.get('/analytics/monthly', {
      params: { year },
    });
    return response.data;
  },

  // Get category analysis
  getCategoryAnalysis: async (period = 'month') => {
    const response = await api.get('/analytics/category', {
      params: { period },
    });
    return response.data;
  },
};
