import api from './api';

export const budgetService = {
  // Get all budgets
  getBudgets: async (params = {}) => {
    const response = await api.get('/budgets', { params });
    return response.data;
  },

  // Get single budget
  getBudget: async (id) => {
    const response = await api.get(`/budgets/${id}`);
    return response.data;
  },

  // Create new budget
  createBudget: async (budgetData) => {
    const response = await api.post('/budgets', budgetData);
    return response.data;
  },

  // Update budget
  updateBudget: async (id, budgetData) => {
    const response = await api.put(`/budgets/${id}`, budgetData);
    return response.data;
  },

  // Delete budget
  deleteBudget: async (id) => {
    const response = await api.delete(`/budgets/${id}`);
    return response.data;
  },

  // Get budget alerts
  getBudgetAlerts: async () => {
    const response = await api.get('/budgets/alerts');
    return response.data;
  },
};
