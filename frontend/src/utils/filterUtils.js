/**
 * Filter transactions based on search term and filter criteria
 * @param {Array} transactions - Array of transaction objects
 * @param {string} searchTerm - Search term to filter by
 * @param {Object} filters - Filter criteria object
 * @returns {Array} Filtered transactions
 */
export const filterTransactions = (transactions, searchTerm, filters) => {
  if (!transactions || transactions.length === 0) {
    return [];
  }

  return transactions.filter(transaction => {
    // Search term filter (title, description, category)
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      const titleMatch = transaction.title?.toLowerCase().includes(searchLower);
      const descriptionMatch = transaction.description?.toLowerCase().includes(searchLower);
      const categoryMatch = transaction.category?.toLowerCase().includes(searchLower);
      const sourceMatch = transaction.source?.toLowerCase().includes(searchLower); // For income
      
      if (!titleMatch && !descriptionMatch && !categoryMatch && !sourceMatch) {
        return false;
      }
    }

    // Category filter
    if (filters.category) {
      const transactionCategory = transaction.category || transaction.source;
      if (transactionCategory !== filters.category) {
        return false;
      }
    }

    // Date range filter
    if (filters.dateFrom || filters.dateTo) {
      const transactionDate = new Date(transaction.date);
      
      if (filters.dateFrom) {
        const fromDate = new Date(filters.dateFrom);
        if (transactionDate < fromDate) {
          return false;
        }
      }
      
      if (filters.dateTo) {
        const toDate = new Date(filters.dateTo);
        // Set to end of day for inclusive filtering
        toDate.setHours(23, 59, 59, 999);
        if (transactionDate > toDate) {
          return false;
        }
      }
    }

    // Amount range filter
    if (filters.amountMin || filters.amountMax) {
      const amount = parseFloat(transaction.amount);
      
      if (filters.amountMin) {
        const minAmount = parseFloat(filters.amountMin);
        if (amount < minAmount) {
          return false;
        }
      }
      
      if (filters.amountMax) {
        const maxAmount = parseFloat(filters.amountMax);
        if (amount > maxAmount) {
          return false;
        }
      }
    }

    return true;
  });
};

/**
 * Get unique categories from transactions
 * @param {Array} transactions - Array of transaction objects
 * @param {string} categoryField - Field name for category ('category' for expenses, 'source' for income)
 * @returns {Array} Array of unique categories
 */
export const getUniqueCategories = (transactions, categoryField = 'category') => {
  if (!transactions || transactions.length === 0) {
    return [];
  }

  const categories = transactions
    .map(transaction => transaction[categoryField])
    .filter(category => category) // Remove null/undefined values
    .filter((category, index, array) => array.indexOf(category) === index) // Remove duplicates
    .sort(); // Sort alphabetically

  return categories;
};

/**
 * Get date range from transactions
 * @param {Array} transactions - Array of transaction objects
 * @returns {Object} Object with minDate and maxDate
 */
export const getDateRange = (transactions) => {
  if (!transactions || transactions.length === 0) {
    return { minDate: null, maxDate: null };
  }

  const dates = transactions
    .map(transaction => new Date(transaction.date))
    .filter(date => !isNaN(date.getTime())); // Remove invalid dates

  if (dates.length === 0) {
    return { minDate: null, maxDate: null };
  }

  const minDate = new Date(Math.min(...dates));
  const maxDate = new Date(Math.max(...dates));

  return {
    minDate: minDate.toISOString().split('T')[0], // Format as YYYY-MM-DD
    maxDate: maxDate.toISOString().split('T')[0]
  };
};

/**
 * Get amount range from transactions
 * @param {Array} transactions - Array of transaction objects
 * @returns {Object} Object with minAmount and maxAmount
 */
export const getAmountRange = (transactions) => {
  if (!transactions || transactions.length === 0) {
    return { minAmount: 0, maxAmount: 0 };
  }

  const amounts = transactions
    .map(transaction => parseFloat(transaction.amount))
    .filter(amount => !isNaN(amount)); // Remove invalid amounts

  if (amounts.length === 0) {
    return { minAmount: 0, maxAmount: 0 };
  }

  return {
    minAmount: Math.min(...amounts),
    maxAmount: Math.max(...amounts)
  };
};
