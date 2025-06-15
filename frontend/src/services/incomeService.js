import api from './api';

export const incomeService = {
  // Get all income
  getIncome: async (params = {}) => {
    const response = await api.get('/income', { params });
    return response.data;
  },

  // Get single income entry
  getIncomeEntry: async (id) => {
    const response = await api.get(`/income/${id}`);
    return response.data;
  },

  // Create new income entry
  createIncome: async (incomeData) => {
    const response = await api.post('/income', incomeData);
    return response.data;
  },

  // Update income entry
  updateIncome: async (id, incomeData) => {
    const response = await api.put(`/income/${id}`, incomeData);
    return response.data;
  },

  // Delete income entry
  deleteIncome: async (id) => {
    const response = await api.delete(`/income/${id}`);
    return response.data;
  },
};
