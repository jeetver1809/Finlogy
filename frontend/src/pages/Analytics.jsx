import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { toast } from 'react-hot-toast';
import {
  CalendarIcon,
  ArrowDownIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline';

// Components
import AnalyticsOverviewCards from '../components/analytics/AnalyticsOverviewCards';
import IncomeExpenseChart from '../components/charts/IncomeExpenseChart';
import CategoryPieChart from '../components/charts/CategoryPieChart';
import MonthlyComparisonChart from '../components/charts/MonthlyComparisonChart';
import TopCategories from '../components/analytics/TopCategories';
import BudgetPerformance from '../components/analytics/BudgetPerformance';
import AnalyticsSkeleton from '../components/skeletons/AnalyticsSkeleton';

// Utilities
import {
  DATE_RANGES,
  getDateRange,
  calculateSavingsRate,
  calculateAverageDailySpending,
  calculateBudgetAdherence,
  prepareIncomeExpenseData,
  prepareCategoryPieData,
  prepareMonthlyData,
  groupByCategory,
  exportToCSV
} from '../utils/analyticsHelpers';
import { cachedApiCall, CACHE_KEYS, CACHE_TTL } from '../utils/cacheSystem';
import { expenseService } from '../services/expenseService';
import { incomeService } from '../services/incomeService';
import { budgetService } from '../services/budgetService';

const Analytics = () => {
  // State management
  const [selectedRange, setSelectedRange] = useState('MONTH');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState({
    transactions: [],
    budgets: [],
    income: [],
    expenses: []
  });

  // Memoized date range
  const dateRange = useMemo(() => getDateRange(selectedRange), [selectedRange]);

  // Fetch analytics data using the same services as other pages
  const fetchAnalyticsData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      console.log('🔄 Fetching real user data for Analytics...');

      // Fetch all required data using the same services as other pages
      const [expensesResponse, incomeResponse, budgetsResponse] = await Promise.all([
        cachedApiCall(
          `${CACHE_KEYS.EXPENSES}_${selectedRange}`,
          () => expenseService.getExpenses(),
          CACHE_TTL.MEDIUM
        ),
        cachedApiCall(
          `${CACHE_KEYS.INCOME}_${selectedRange}`,
          () => incomeService.getIncome(),
          CACHE_TTL.MEDIUM
        ),
        cachedApiCall(
          CACHE_KEYS.BUDGETS,
          () => budgetService.getBudgets(),
          CACHE_TTL.MEDIUM
        )
      ]);

      // Extract data from service responses
      const expenses = expensesResponse?.data || [];
      const income = incomeResponse?.data || [];
      const budgets = budgetsResponse?.data || [];

      // Combine transactions for analytics
      const allTransactions = [
        ...expenses.map(exp => ({ ...exp, type: 'expense' })),
        ...income.map(inc => ({ ...inc, type: 'income' }))
      ];

      console.log('✅ Analytics data loaded:', {
        expenses: expenses.length,
        income: income.length,
        budgets: budgets.length,
        transactions: allTransactions.length
      });

      setData({
        transactions: allTransactions,
        budgets: budgets,
        income: income,
        expenses: expenses
      });
    } catch (err) {
      console.error('Failed to fetch analytics data:', err);
      setError('Failed to load analytics data. Please try again.');
      toast.error('Failed to load analytics data');

      // Set empty data instead of mock data
      setData({
        transactions: [],
        budgets: [],
        income: [],
        expenses: []
      });
    } finally {
      setLoading(false);
    }
  }, [selectedRange]);

  // Load data on mount and range change
  useEffect(() => {
    fetchAnalyticsData();
  }, [fetchAnalyticsData]);

  // Memoized calculations for performance
  const analytics = useMemo(() => {
    const { transactions, budgets, income, expenses } = data;

    // Ensure all data arrays exist
    const safeTransactions = Array.isArray(transactions) ? transactions : [];
    const safeBudgets = Array.isArray(budgets) ? budgets : [];
    const safeIncome = Array.isArray(income) ? income : [];
    const safeExpenses = Array.isArray(expenses) ? expenses : [];

    // Ensure dateRange exists
    if (!dateRange || !dateRange.startDate || !dateRange.endDate) {
      console.warn('Invalid date range:', dateRange);
      return {
        totalIncome: 0,
        totalExpenses: 0,
        savingsRate: 0,
        averageDailySpending: 0,
        budgetAdherence: 0,
        incomeExpenseData: [],
        categoryData: [],
        monthlyData: [],
        topCategories: []
      };
    }

    // Filter data by date range with error handling
    const filteredTransactions = safeTransactions.filter(t => {
      if (!t || !t.date) return false;
      try {
        const transactionDate = new Date(t.date);
        return transactionDate >= dateRange.startDate && transactionDate <= dateRange.endDate;
      } catch (error) {
        console.warn('Invalid transaction date:', t);
        return false;
      }
    });

    const filteredIncome = safeIncome.filter(i => {
      if (!i || !i.date) return false;
      try {
        const incomeDate = new Date(i.date);
        return incomeDate >= dateRange.startDate && incomeDate <= dateRange.endDate;
      } catch (error) {
        console.warn('Invalid income date:', i);
        return false;
      }
    });

    const filteredExpenses = safeExpenses.filter(e => {
      if (!e || !e.date) return false;
      try {
        const expenseDate = new Date(e.date);
        return expenseDate >= dateRange.startDate && expenseDate <= dateRange.endDate;
      } catch (error) {
        console.warn('Invalid expense date:', e);
        return false;
      }
    });

    // Calculate totals with error handling
    const totalIncome = filteredIncome.reduce((sum, item) => {
      return sum + (typeof item.amount === 'number' ? item.amount : 0);
    }, 0);

    const totalExpenses = filteredExpenses.reduce((sum, item) => {
      return sum + (typeof item.amount === 'number' ? Math.abs(item.amount) : 0);
    }, 0);

    // Calculate metrics with safety checks
    const savingsRate = calculateSavingsRate(totalIncome, totalExpenses);
    const averageDailySpending = calculateAverageDailySpending(
      totalExpenses,
      DATE_RANGES[selectedRange]?.days || 30
    );
    const budgetAdherence = calculateBudgetAdherence(safeBudgets);

    // Prepare chart data with error handling
    const incomeExpenseData = prepareIncomeExpenseData(filteredTransactions, dateRange);
    const categoryData = prepareCategoryPieData(filteredExpenses);
    const monthlyData = prepareMonthlyData(safeTransactions);
    const topCategories = groupByCategory(filteredExpenses);

    return {
      totalIncome,
      totalExpenses,
      savingsRate,
      averageDailySpending,
      budgetAdherence,
      incomeExpenseData,
      categoryData,
      monthlyData,
      topCategories
    };
  }, [data, dateRange, selectedRange]);

  // Handle date range change
  const handleRangeChange = useCallback((range) => {
    setSelectedRange(range);
  }, []);

  // Handle data export
  const handleExport = useCallback(() => {
    try {
      if (!analytics || !analytics.incomeExpenseData || !Array.isArray(analytics.incomeExpenseData)) {
        toast.error('No data available to export');
        return;
      }

      const exportData = analytics.incomeExpenseData.map(item => ({
        Date: item?.date || '',
        Income: item?.income || 0,
        Expenses: item?.expenses || 0,
        Net: item?.net || 0
      }));

      if (exportData.length === 0) {
        toast.error('No data available to export');
        return;
      }

      exportToCSV(exportData, `analytics-${selectedRange.toLowerCase()}-${new Date().toISOString().split('T')[0]}`);
      toast.success('Analytics data exported successfully');
    } catch (err) {
      console.error('Export failed:', err);
      toast.error('Failed to export data');
    }
  }, [analytics, selectedRange]);

  // Loading state
  if (loading) {
    return <AnalyticsSkeleton />;
  }

  // Error state
  if (error) {
    return (
      <div className="p-8">
        <div className="text-center">
          <div className="w-16 h-16 mx-auto mb-4 bg-red-100 dark:bg-red-900/20 rounded-full flex items-center justify-center">
            <ChartBarIcon className="w-8 h-8 text-red-600 dark:text-red-400" />
          </div>
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
            Failed to Load Analytics
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">{error}</p>
          <button
            onClick={fetchAnalyticsData}
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md transition-colors"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  // Check if we have any real data
  const hasData = data.transactions.length > 0 || data.income.length > 0 || data.expenses.length > 0;

  // Empty state component
  const EmptyState = () => (
    <div className="text-center py-12">
      <div className="w-24 h-24 mx-auto mb-6 bg-gray-100 dark:bg-gray-700 rounded-full flex items-center justify-center">
        <ChartBarIcon className="w-12 h-12 text-gray-400" />
      </div>
      <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
        No Financial Data Yet
      </h3>
      <p className="text-gray-600 dark:text-gray-400 mb-6 max-w-md mx-auto">
        Start by adding some expenses, income, or budgets to see your financial analytics and insights here.
      </p>
      <div className="flex flex-col sm:flex-row gap-3 justify-center">
        <button
          onClick={() => window.location.href = '#expenses'}
          className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg transition-colors"
        >
          Add Expenses
        </button>
        <button
          onClick={() => window.location.href = '#income'}
          className="bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded-lg transition-colors"
        >
          Add Income
        </button>
        <button
          onClick={() => window.location.href = '#budgets'}
          className="bg-purple-600 hover:bg-purple-700 text-white px-6 py-2 rounded-lg transition-colors"
        >
          Create Budgets
        </button>
      </div>
    </div>
  );

  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center space-y-4 sm:space-y-0">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Analytics</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            {hasData
              ? 'Insights into your financial patterns and trends'
              : 'Add some financial data to see analytics'
            }
          </p>
        </div>

        <div className="flex items-center space-x-4">
          {/* Date Range Selector */}
          <div className="relative">
            <select
              value={selectedRange}
              onChange={(e) => handleRangeChange(e.target.value)}
              className="appearance-none bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2 pr-8 text-sm font-medium text-gray-700 dark:text-gray-300 hover:border-gray-400 dark:hover:border-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
            >
              {Object.entries(DATE_RANGES).map(([key, range]) => (
                <option key={key} value={key}>
                  {range.label}
                </option>
              ))}
            </select>
            <CalendarIcon className="absolute right-2 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
          </div>

          {/* Export Button */}
          <button
            onClick={handleExport}
            className="flex items-center space-x-2 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 px-4 py-2 rounded-lg transition-colors"
          >
            <ArrowDownIcon className="w-4 h-4" />
            <span className="text-sm font-medium">Export</span>
          </button>
        </div>
      </div>

      {/* Show empty state if no data, otherwise show analytics */}
      {!hasData ? (
        <EmptyState />
      ) : (
        <>
          {/* Overview Cards */}
          <AnalyticsOverviewCards
            totalIncome={analytics.totalIncome}
            totalExpenses={analytics.totalExpenses}
            averageDailySpending={analytics.averageDailySpending}
            savingsRate={analytics.savingsRate}
            budgetAdherence={analytics.budgetAdherence}
          />

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Income vs Expenses Chart */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow border border-gray-200 dark:border-gray-700 transition-base interactive-card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Income vs Expenses Trend
          </h3>
          <IncomeExpenseChart data={analytics.incomeExpenseData} height={320} />
        </div>

        {/* Category Breakdown */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow border border-gray-200 dark:border-gray-700 transition-base interactive-card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Expense Categories
          </h3>
          <CategoryPieChart data={analytics.categoryData} height={320} />
        </div>
      </div>

      {/* Bottom Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Monthly Comparison */}
        <div className="lg:col-span-2 bg-white dark:bg-gray-800 p-6 rounded-lg shadow border border-gray-200 dark:border-gray-700 transition-base interactive-card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Monthly Comparison
          </h3>
          <MonthlyComparisonChart data={analytics.monthlyData} height={280} />
        </div>

        {/* Top Categories */}
        <TopCategories
          categories={analytics.topCategories}
          totalAmount={analytics.totalExpenses}
          maxItems={5}
        />
      </div>

      {/* Budget Performance */}
      <BudgetPerformance budgets={data.budgets} />
        </>
      )}
    </div>
  );
};

export default Analytics;
