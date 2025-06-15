import { format, subDays, startOfMonth, endOfMonth, eachDayOfInterval, eachMonthOfInterval } from 'date-fns';

// Date range options for analytics
export const DATE_RANGES = {
  WEEK: { label: 'Last 7 days', days: 7 },
  MONTH: { label: 'Last 30 days', days: 30 },
  QUARTER: { label: 'Last 90 days', days: 90 },
  YEAR: { label: 'Last 1 year', days: 365 }
};

// Get date range based on selection
export const getDateRange = (range) => {
  const endDate = new Date();
  const startDate = subDays(endDate, DATE_RANGES[range].days);
  return { startDate, endDate };
};

// Calculate savings rate
export const calculateSavingsRate = (totalIncome, totalExpenses) => {
  if (totalIncome === 0) return 0;
  const savings = totalIncome - totalExpenses;
  return Math.round((savings / totalIncome) * 100);
};

// Calculate average daily spending
export const calculateAverageDailySpending = (expenses, days) => {
  if (days === 0) return 0;
  return expenses / days;
};

// Calculate budget adherence score
export const calculateBudgetAdherence = (budgets) => {
  if (!budgets || budgets.length === 0) return 0;
  
  const adherenceScores = budgets.map(budget => {
    const spentPercentage = (budget.spent / budget.amount) * 100;
    if (spentPercentage <= 80) return 100; // Excellent
    if (spentPercentage <= 100) return 80; // Good
    if (spentPercentage <= 120) return 60; // Warning
    return 30; // Over budget
  });
  
  return Math.round(adherenceScores.reduce((sum, score) => sum + score, 0) / adherenceScores.length);
};

// Group transactions by category
export const groupByCategory = (transactions) => {
  const categoryTotals = {};
  
  transactions.forEach(transaction => {
    const category = transaction.category || 'Other';
    categoryTotals[category] = (categoryTotals[category] || 0) + Math.abs(transaction.amount);
  });
  
  return Object.entries(categoryTotals)
    .map(([category, amount]) => ({ category, amount }))
    .sort((a, b) => b.amount - a.amount);
};

// Calculate spending trend
export const calculateSpendingTrend = (currentPeriod, previousPeriod) => {
  if (previousPeriod === 0) return { trend: 'stable', percentage: 0 };
  
  const change = ((currentPeriod - previousPeriod) / previousPeriod) * 100;
  
  if (Math.abs(change) < 5) return { trend: 'stable', percentage: change };
  if (change > 0) return { trend: 'increasing', percentage: change };
  return { trend: 'decreasing', percentage: Math.abs(change) };
};

// Prepare chart data for income vs expenses
export const prepareIncomeExpenseData = (transactions, dateRange) => {
  if (!transactions || !Array.isArray(transactions) || !dateRange) {
    return [];
  }

  try {
    const { startDate, endDate } = dateRange;
    if (!startDate || !endDate) {
      return [];
    }

    const days = eachDayOfInterval({ start: startDate, end: endDate });

    return days.map(day => {
      const dayStr = format(day, 'yyyy-MM-dd');
      const dayTransactions = transactions.filter(t => {
        try {
          return t && t.date && format(new Date(t.date), 'yyyy-MM-dd') === dayStr;
        } catch (error) {
          console.warn('Invalid date in transaction:', t);
          return false;
        }
      });

      const income = dayTransactions
        .filter(t => t.type === 'income')
        .reduce((sum, t) => sum + (t.amount || 0), 0);

      const expenses = dayTransactions
        .filter(t => t.type === 'expense')
        .reduce((sum, t) => sum + Math.abs(t.amount || 0), 0);

      return {
        date: format(day, 'MMM dd'),
        income,
        expenses,
        net: income - expenses
      };
    });
  } catch (error) {
    console.error('Error preparing income expense data:', error);
    return [];
  }
};

// Prepare monthly comparison data
export const prepareMonthlyData = (transactions) => {
  if (!transactions || !Array.isArray(transactions)) {
    return [];
  }

  try {
    const months = eachMonthOfInterval({
      start: subDays(new Date(), 365),
      end: new Date()
    });

    return months.map(month => {
      const monthStart = startOfMonth(month);
      const monthEnd = endOfMonth(month);

      const monthTransactions = transactions.filter(t => {
        try {
          if (!t || !t.date) return false;
          const transactionDate = new Date(t.date);
          return transactionDate >= monthStart && transactionDate <= monthEnd;
        } catch (error) {
          console.warn('Invalid date in transaction:', t);
          return false;
        }
      });

      const income = monthTransactions
        .filter(t => t.type === 'income')
        .reduce((sum, t) => sum + (t.amount || 0), 0);

      const expenses = monthTransactions
        .filter(t => t.type === 'expense')
        .reduce((sum, t) => sum + Math.abs(t.amount || 0), 0);

      return {
        month: format(month, 'MMM yyyy'),
        income,
        expenses,
        savings: income - expenses
      };
    });
  } catch (error) {
    console.error('Error preparing monthly data:', error);
    return [];
  }
};

// Prepare pie chart data for categories
export const prepareCategoryPieData = (expenses) => {
  if (!expenses || !Array.isArray(expenses) || expenses.length === 0) {
    return [];
  }

  const categoryData = groupByCategory(expenses);
  if (categoryData.length === 0) {
    return [];
  }

  const total = categoryData.reduce((sum, item) => sum + item.amount, 0);

  // Prevent division by zero
  if (total === 0) {
    return [];
  }

  return categoryData.map((item, index) => ({
    name: item.category,
    value: item.amount,
    percentage: Math.round((item.amount / total) * 100),
    color: getCategoryColor(index)
  }));
};

// Get color for category (consistent colors)
export const getCategoryColor = (index) => {
  const colors = [
    '#3B82F6', // Blue
    '#EF4444', // Red
    '#10B981', // Green
    '#F59E0B', // Yellow
    '#8B5CF6', // Purple
    '#F97316', // Orange
    '#06B6D4', // Cyan
    '#84CC16', // Lime
    '#EC4899', // Pink
    '#6B7280'  // Gray
  ];
  return colors[index % colors.length];
};

// Format currency for display
export const formatCurrency = (amount, currency = 'INR') => {
  return new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency: currency,
    minimumFractionDigits: 0,
    maximumFractionDigits: 0
  }).format(amount);
};

// Calculate percentage change
export const calculatePercentageChange = (current, previous) => {
  if (previous === 0) return current > 0 ? 100 : 0;
  return Math.round(((current - previous) / previous) * 100);
};

// Get trend icon and color
export const getTrendIndicator = (percentage) => {
  if (percentage > 0) {
    return { icon: '↗', color: 'text-green-600 dark:text-green-400', trend: 'up' };
  } else if (percentage < 0) {
    return { icon: '↘', color: 'text-red-600 dark:text-red-400', trend: 'down' };
  }
  return { icon: '→', color: 'text-gray-600 dark:text-gray-400', trend: 'stable' };
};

// Export data to CSV
export const exportToCSV = (data, filename) => {
  const csvContent = convertToCSV(data);
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  
  if (link.download !== undefined) {
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', `${filename}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }
};

// Convert data to CSV format
const convertToCSV = (data) => {
  if (!data || data.length === 0) return '';
  
  const headers = Object.keys(data[0]);
  const csvHeaders = headers.join(',');
  
  const csvRows = data.map(row => 
    headers.map(header => {
      const value = row[header];
      return typeof value === 'string' ? `"${value}"` : value;
    }).join(',')
  );
  
  return [csvHeaders, ...csvRows].join('\n');
};

export default {
  DATE_RANGES,
  getDateRange,
  calculateSavingsRate,
  calculateAverageDailySpending,
  calculateBudgetAdherence,
  groupByCategory,
  calculateSpendingTrend,
  prepareIncomeExpenseData,
  prepareMonthlyData,
  prepareCategoryPieData,
  getCategoryColor,
  formatCurrency,
  calculatePercentageChange,
  getTrendIndicator,
  exportToCSV
};
