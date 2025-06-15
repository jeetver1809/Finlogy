// Analytics integration utilities for cross-section data correlation

import { format, startOfMonth, endOfMonth, subDays } from 'date-fns';
import { 
  calculateSavingsRate, 
  calculateBudgetAdherence, 
  groupByCategory,
  formatCurrency 
} from './analyticsHelpers';

// Navigation utilities for deep-linking
export const createAnalyticsUrl = (filters = {}) => {
  const params = new URLSearchParams();
  
  if (filters.dateRange) params.set('range', filters.dateRange);
  if (filters.category) params.set('category', filters.category);
  if (filters.type) params.set('type', filters.type);
  if (filters.budgetId) params.set('budget', filters.budgetId);
  
  return `/analytics${params.toString() ? `?${params.toString()}` : ''}`;
};

// Parse URL parameters for Analytics page
export const parseAnalyticsFilters = (searchParams) => {
  return {
    dateRange: searchParams.get('range') || 'MONTH',
    category: searchParams.get('category') || null,
    type: searchParams.get('type') || null,
    budgetId: searchParams.get('budget') || null
  };
};

// Calculate mini-analytics for dashboard widgets
export const calculateDashboardMetrics = (transactions, budgets, income, expenses) => {
  const currentMonth = {
    start: startOfMonth(new Date()),
    end: endOfMonth(new Date())
  };
  
  // Filter current month data
  const currentMonthTransactions = transactions.filter(t => {
    const date = new Date(t.date);
    return date >= currentMonth.start && date <= currentMonth.end;
  });
  
  const currentMonthIncome = income.filter(i => {
    const date = new Date(i.date);
    return date >= currentMonth.start && date <= currentMonth.end;
  });
  
  const currentMonthExpenses = expenses.filter(e => {
    const date = new Date(e.date);
    return date >= currentMonth.start && date <= currentMonth.end;
  });
  
  // Calculate metrics
  const totalIncome = currentMonthIncome.reduce((sum, i) => sum + i.amount, 0);
  const totalExpenses = currentMonthExpenses.reduce((sum, e) => sum + Math.abs(e.amount), 0);
  const savingsRate = calculateSavingsRate(totalIncome, totalExpenses);
  const budgetAdherence = calculateBudgetAdherence(budgets);
  
  // Top spending category
  const categorySpending = groupByCategory(currentMonthExpenses);
  const topCategory = categorySpending[0] || { category: 'No expenses', amount: 0 };
  
  // Spending trend (compare with last month)
  const lastMonth = {
    start: startOfMonth(subDays(currentMonth.start, 1)),
    end: endOfMonth(subDays(currentMonth.start, 1))
  };
  
  const lastMonthExpenses = expenses.filter(e => {
    const date = new Date(e.date);
    return date >= lastMonth.start && date <= lastMonth.end;
  });
  
  const lastMonthTotal = lastMonthExpenses.reduce((sum, e) => sum + Math.abs(e.amount), 0);
  const spendingTrend = lastMonthTotal > 0 
    ? ((totalExpenses - lastMonthTotal) / lastMonthTotal) * 100 
    : 0;
  
  return {
    savingsRate,
    budgetAdherence,
    topCategory,
    spendingTrend,
    totalIncome,
    totalExpenses,
    netIncome: totalIncome - totalExpenses
  };
};

// Calculate expense-specific analytics
export const calculateExpenseAnalytics = (expenses, budgets, category = null) => {
  const filteredExpenses = category 
    ? expenses.filter(e => e.category === category)
    : expenses;
  
  // Category breakdown
  const categoryBreakdown = groupByCategory(filteredExpenses);
  
  // Budget impact for category
  const categoryBudget = budgets.find(b => 
    b.category === (category || '').toLowerCase().replace(/\s+/g, '-')
  );
  
  const categorySpent = category 
    ? filteredExpenses.reduce((sum, e) => sum + Math.abs(e.amount), 0)
    : 0;
  
  const budgetImpact = categoryBudget ? {
    budget: categoryBudget,
    spent: categorySpent,
    remaining: categoryBudget.amount - categorySpent,
    percentage: (categorySpent / categoryBudget.amount) * 100
  } : null;
  
  // Spending pattern (last 7 days)
  const last7Days = subDays(new Date(), 7);
  const recentExpenses = filteredExpenses.filter(e => new Date(e.date) >= last7Days);
  const dailyAverage = recentExpenses.length > 0 
    ? recentExpenses.reduce((sum, e) => sum + Math.abs(e.amount), 0) / 7
    : 0;
  
  return {
    categoryBreakdown,
    budgetImpact,
    dailyAverage,
    totalSpent: filteredExpenses.reduce((sum, e) => sum + Math.abs(e.amount), 0),
    transactionCount: filteredExpenses.length
  };
};

// Calculate income-specific analytics
export const calculateIncomeAnalytics = (income, expenses) => {
  const currentMonth = {
    start: startOfMonth(new Date()),
    end: endOfMonth(new Date())
  };
  
  const currentMonthIncome = income.filter(i => {
    const date = new Date(i.date);
    return date >= currentMonth.start && date <= currentMonth.end;
  });
  
  const currentMonthExpenses = expenses.filter(e => {
    const date = new Date(e.date);
    return date >= currentMonth.start && date <= currentMonth.end;
  });
  
  const totalIncome = currentMonthIncome.reduce((sum, i) => sum + i.amount, 0);
  const totalExpenses = currentMonthExpenses.reduce((sum, e) => sum + Math.abs(e.amount), 0);
  
  // Income vs expenses correlation
  const correlation = {
    income: totalIncome,
    expenses: totalExpenses,
    net: totalIncome - totalExpenses,
    savingsRate: calculateSavingsRate(totalIncome, totalExpenses)
  };
  
  // Income sources breakdown
  const sourceBreakdown = currentMonthIncome.reduce((acc, income) => {
    const source = income.source || 'Other';
    acc[source] = (acc[source] || 0) + income.amount;
    return acc;
  }, {});
  
  // Trend analysis (compare with last month)
  const lastMonth = {
    start: startOfMonth(subDays(currentMonth.start, 1)),
    end: endOfMonth(subDays(currentMonth.start, 1))
  };
  
  const lastMonthIncome = income.filter(i => {
    const date = new Date(i.date);
    return date >= lastMonth.start && date <= lastMonth.end;
  });
  
  const lastMonthTotal = lastMonthIncome.reduce((sum, i) => sum + i.amount, 0);
  const incomeTrend = lastMonthTotal > 0 
    ? ((totalIncome - lastMonthTotal) / lastMonthTotal) * 100 
    : 0;
  
  return {
    correlation,
    sourceBreakdown,
    incomeTrend,
    monthlyAverage: totalIncome,
    projectedAnnual: totalIncome * 12
  };
};

// Calculate budget-specific analytics
export const calculateBudgetAnalytics = (budgets, expenses) => {
  return budgets.map(budget => {
    // Find expenses for this budget category
    const categoryExpenses = expenses.filter(e => 
      e.category === budget.category || 
      e.category === budget.name.toLowerCase().replace(/\s+/g, '-')
    );
    
    const spent = categoryExpenses.reduce((sum, e) => sum + Math.abs(e.amount), 0);
    const remaining = budget.amount - spent;
    const percentage = (spent / budget.amount) * 100;
    
    // Spending pattern analysis
    const last7Days = subDays(new Date(), 7);
    const recentSpending = categoryExpenses.filter(e => new Date(e.date) >= last7Days);
    const weeklyTrend = recentSpending.reduce((sum, e) => sum + Math.abs(e.amount), 0);
    const projectedMonthly = (weeklyTrend / 7) * 30;
    
    // Status determination
    let status = 'on-track';
    if (percentage >= 100) status = 'exceeded';
    else if (percentage >= (budget.alertThreshold || 80)) status = 'warning';
    
    return {
      ...budget,
      spent,
      remaining,
      percentage,
      status,
      weeklyTrend,
      projectedMonthly,
      isOnTrack: projectedMonthly <= budget.amount,
      daysRemaining: Math.ceil((endOfMonth(new Date()) - new Date()) / (1000 * 60 * 60 * 24))
    };
  });
};

// Cache invalidation utilities
export const invalidateAnalyticsCache = (cacheManager, type = 'all') => {
  const patterns = {
    all: ['analytics', 'dashboard', 'expenses', 'income', 'budgets'],
    transactions: ['analytics', 'dashboard'],
    budgets: ['analytics', 'budgets'],
    expenses: ['analytics', 'expenses'],
    income: ['analytics', 'income']
  };
  
  const patternsToInvalidate = patterns[type] || patterns.all;
  patternsToInvalidate.forEach(pattern => {
    if (cacheManager && typeof cacheManager.invalidateCache === 'function') {
      cacheManager.invalidateCache(pattern);
    }
  });
};

export default {
  createAnalyticsUrl,
  parseAnalyticsFilters,
  calculateDashboardMetrics,
  calculateExpenseAnalytics,
  calculateIncomeAnalytics,
  calculateBudgetAnalytics,
  invalidateAnalyticsCache
};
