import api from './api';

class SearchService {
  constructor() {
    this.cache = new Map();
    this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
  }

  // Get cached data or fetch fresh data
  async getCachedData(key, fetchFunction) {
    const cached = this.cache.get(key);
    const now = Date.now();

    if (cached && (now - cached.timestamp) < this.cacheTimeout) {
      return cached.data;
    }

    try {
      const data = await fetchFunction();
      this.cache.set(key, {
        data,
        timestamp: now
      });
      return data;
    } catch (error) {
      console.error(`Error fetching ${key}:`, error);
      // Return cached data if available, even if expired
      return cached ? cached.data : null;
    }
  }

  // Get all searchable data
  async getAllSearchData() {
    try {
      const [expenses, income, budgets] = await Promise.all([
        this.getCachedData('expenses', () => this.getExpenses()),
        this.getCachedData('income', () => this.getIncome()),
        this.getCachedData('budgets', () => this.getBudgets())
      ]);

      // Extract unique categories
      const categories = new Set();
      
      expenses?.forEach(expense => {
        if (expense.category) categories.add(expense.category);
      });
      
      income?.forEach(inc => {
        if (inc.source) categories.add(inc.source);
      });
      
      budgets?.forEach(budget => {
        if (budget.category) categories.add(budget.category);
      });

      return {
        expenses: expenses || [],
        income: income || [],
        budgets: budgets || [],
        categories: Array.from(categories).sort()
      };
    } catch (error) {
      console.error('Error getting search data:', error);
      return {
        expenses: [],
        income: [],
        budgets: [],
        categories: []
      };
    }
  }

  // Get expenses
  async getExpenses() {
    try {
      const response = await api.get('/expenses');
      return response.data.success ? response.data.data : [];
    } catch (error) {
      console.error('Error fetching expenses:', error);
      return [];
    }
  }

  // Get income
  async getIncome() {
    try {
      const response = await api.get('/income');
      return response.data.success ? response.data.data : [];
    } catch (error) {
      console.error('Error fetching income:', error);
      return [];
    }
  }

  // Get budgets
  async getBudgets() {
    try {
      const response = await api.get('/budgets');
      return response.data.success ? response.data.data : [];
    } catch (error) {
      console.error('Error fetching budgets:', error);
      return [];
    }
  }

  // Perform advanced search with filters
  async search(query, filters = {}) {
    const data = await this.getAllSearchData();
    const results = [];
    const searchTerm = query.toLowerCase().trim();

    if (!searchTerm) return results;

    // Helper functions
    const matchesText = (text) => {
      return text && text.toLowerCase().includes(searchTerm);
    };

    const isInDateRange = (date, range) => {
      if (range === 'all') return true;
      
      const itemDate = new Date(date);
      const now = new Date();
      const diffTime = now - itemDate;
      
      switch (range) {
        case 'week':
          return diffTime <= 7 * 24 * 60 * 60 * 1000;
        case 'month':
          return diffTime <= 30 * 24 * 60 * 60 * 1000;
        case 'year':
          return diffTime <= 365 * 24 * 60 * 60 * 1000;
        default:
          return true;
      }
    };

    const isInAmountRange = (amount, range) => {
      if (range === 'all') return true;
      
      switch (range) {
        case 'low':
          return amount <= 1000;
        case 'medium':
          return amount > 1000 && amount <= 10000;
        case 'high':
          return amount > 10000;
        default:
          return true;
      }
    };

    // Search expenses
    if (filters.type === 'all' || filters.type === 'expenses') {
      data.expenses.forEach(expense => {
        const matches = 
          matchesText(expense.title) ||
          matchesText(expense.description) ||
          matchesText(expense.category);

        if (matches && 
            isInDateRange(expense.date, filters.dateRange) &&
            isInAmountRange(expense.amount, filters.amountRange) &&
            (filters.category === 'all' || expense.category === filters.category)) {
          
          results.push({
            ...expense,
            type: 'expense',
            searchScore: this.calculateSearchScore(expense, searchTerm),
            route: '/expenses'
          });
        }
      });
    }

    // Search income
    if (filters.type === 'all' || filters.type === 'income') {
      data.income.forEach(income => {
        const matches = 
          matchesText(income.title) ||
          matchesText(income.description) ||
          matchesText(income.source);

        if (matches && 
            isInDateRange(income.date, filters.dateRange) &&
            isInAmountRange(income.amount, filters.amountRange)) {
          
          results.push({
            ...income,
            type: 'income',
            searchScore: this.calculateSearchScore(income, searchTerm),
            route: '/income'
          });
        }
      });
    }

    // Search budgets
    if (filters.type === 'all' || filters.type === 'budgets') {
      data.budgets.forEach(budget => {
        const matches = 
          matchesText(budget.name) ||
          matchesText(budget.category) ||
          matchesText(budget.description);

        if (matches &&
            (filters.category === 'all' || budget.category === filters.category)) {
          
          results.push({
            ...budget,
            type: 'budget',
            searchScore: this.calculateSearchScore(budget, searchTerm),
            route: '/budgets'
          });
        }
      });
    }

    // Sort by search score and return top results
    return results
      .sort((a, b) => b.searchScore - a.searchScore)
      .slice(0, 20);
  }

  // Calculate search relevance score
  calculateSearchScore(item, searchTerm) {
    let score = 0;
    const term = searchTerm.toLowerCase();

    // Title/name exact match gets highest score
    const title = (item.title || item.name || '').toLowerCase();
    if (title === term) score += 100;
    else if (title.startsWith(term)) score += 80;
    else if (title.includes(term)) score += 60;

    // Description match
    const description = (item.description || '').toLowerCase();
    if (description.includes(term)) score += 30;

    // Category match
    const category = (item.category || item.source || '').toLowerCase();
    if (category === term) score += 50;
    else if (category.includes(term)) score += 25;

    // Recency bonus (more recent items get higher score)
    if (item.date) {
      const daysSinceCreated = (Date.now() - new Date(item.date)) / (1000 * 60 * 60 * 24);
      if (daysSinceCreated <= 7) score += 10;
      else if (daysSinceCreated <= 30) score += 5;
    }

    return score;
  }

  // Get search suggestions based on existing data
  async getSearchSuggestions(query) {
    if (!query || query.length < 2) return [];

    const data = await this.getAllSearchData();
    const suggestions = new Set();
    const term = query.toLowerCase();

    // Add title/name suggestions
    [...data.expenses, ...data.income, ...data.budgets].forEach(item => {
      const title = item.title || item.name || '';
      if (title.toLowerCase().includes(term)) {
        suggestions.add(title);
      }
    });

    // Add category suggestions
    data.categories.forEach(category => {
      if (category.toLowerCase().includes(term)) {
        suggestions.add(category);
      }
    });

    return Array.from(suggestions).slice(0, 8);
  }

  // Clear cache
  clearCache() {
    this.cache.clear();
  }

  // Get cache stats
  getCacheStats() {
    return {
      size: this.cache.size,
      keys: Array.from(this.cache.keys()),
      timeout: this.cacheTimeout
    };
  }
}

// Create and export singleton instance
export const searchService = new SearchService();
export default searchService;
