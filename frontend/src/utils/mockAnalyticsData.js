// Mock data for Analytics page testing
import { subDays, format } from 'date-fns';

// Generate mock transactions for the last 90 days
const generateMockTransactions = () => {
  const transactions = [];
  const categories = ['Food & Dining', 'Transportation', 'Shopping', 'Entertainment', 'Bills & Utilities', 'Healthcare', 'Groceries'];
  const incomeSources = ['Salary', 'Freelance', 'Investment', 'Bonus'];
  
  for (let i = 0; i < 90; i++) {
    const date = subDays(new Date(), i);
    
    // Generate 1-3 transactions per day
    const transactionsPerDay = Math.floor(Math.random() * 3) + 1;
    
    for (let j = 0; j < transactionsPerDay; j++) {
      // 70% chance of expense, 30% chance of income
      const isExpense = Math.random() < 0.7;
      
      if (isExpense) {
        transactions.push({
          _id: `exp_${i}_${j}`,
          type: 'expense',
          title: `${categories[Math.floor(Math.random() * categories.length)]} Expense`,
          amount: Math.floor(Math.random() * 500) + 50, // 50-550
          category: categories[Math.floor(Math.random() * categories.length)],
          date: date.toISOString(),
          description: 'Mock expense transaction'
        });
      } else {
        transactions.push({
          _id: `inc_${i}_${j}`,
          type: 'income',
          title: `${incomeSources[Math.floor(Math.random() * incomeSources.length)]} Income`,
          amount: Math.floor(Math.random() * 2000) + 1000, // 1000-3000
          source: incomeSources[Math.floor(Math.random() * incomeSources.length)],
          date: date.toISOString(),
          description: 'Mock income transaction'
        });
      }
    }
  }
  
  return transactions.sort((a, b) => new Date(b.date) - new Date(a.date));
};

// Generate mock budgets
const generateMockBudgets = () => {
  const categories = ['Food & Dining', 'Transportation', 'Shopping', 'Entertainment', 'Bills & Utilities'];
  
  return categories.map((category, index) => {
    const amount = Math.floor(Math.random() * 2000) + 1000; // 1000-3000
    const spent = Math.floor(Math.random() * amount * 1.2); // Can be over budget
    
    return {
      _id: `budget_${index}`,
      name: `${category} Budget`,
      category: category.toLowerCase().replace(/\s+/g, '-'),
      amount,
      spent,
      period: 'monthly',
      alertThreshold: 80,
      startDate: new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString(),
      endDate: new Date(new Date().getFullYear(), new Date().getMonth() + 1, 0).toISOString(),
      description: `Monthly budget for ${category}`
    };
  });
};

// Mock API responses
export const mockApiResponses = {
  transactions: {
    success: true,
    data: generateMockTransactions()
  },
  
  budgets: {
    success: true,
    data: generateMockBudgets()
  },
  
  income: {
    success: true,
    data: generateMockTransactions().filter(t => t.type === 'income')
  },
  
  expenses: {
    success: true,
    data: generateMockTransactions().filter(t => t.type === 'expense')
  }
};

// Mock fetch function for analytics
export const mockFetch = (url) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      let response;
      
      if (url.includes('/api/transactions')) {
        response = mockApiResponses.transactions;
      } else if (url.includes('/api/budgets')) {
        response = mockApiResponses.budgets;
      } else if (url.includes('/api/income')) {
        response = mockApiResponses.income;
      } else if (url.includes('/api/expenses')) {
        response = mockApiResponses.expenses;
      } else {
        response = { success: false, message: 'Not found' };
      }
      
      resolve({
        ok: true,
        json: () => Promise.resolve(response.data || response)
      });
    }, Math.random() * 500 + 200); // 200-700ms delay
  });
};

export default {
  mockApiResponses,
  mockFetch,
  generateMockTransactions,
  generateMockBudgets
};
