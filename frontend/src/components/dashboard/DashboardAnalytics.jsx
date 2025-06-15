import React, { memo, useMemo } from 'react';
import { 
  BanknotesIcon, 
  ChartBarIcon, 
  TagIcon,
  TrendingUpIcon as ArrowTrendingUpIcon 
} from '@heroicons/react/24/outline';
import AnalyticsWidget, { MiniChartWidget, CategoryInsightWidget } from '../analytics/AnalyticsWidget';
import { calculateDashboardMetrics } from '../../utils/analyticsIntegration';
import { formatCurrency } from '../../utils/analyticsHelpers';

const DashboardAnalytics = memo(({ 
  transactions = [], 
  budgets = [], 
  income = [], 
  expenses = [],
  onNavigateToAnalytics 
}) => {
  
  // Calculate dashboard metrics
  const metrics = useMemo(() => {
    return calculateDashboardMetrics(transactions, budgets, income, expenses);
  }, [transactions, budgets, income, expenses]);

  // Prepare mini chart data for spending trend
  const spendingTrendData = useMemo(() => {
    // Get last 7 days of expenses for mini chart
    const last7Days = [];
    for (let i = 6; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dayExpenses = expenses.filter(e => {
        const expenseDate = new Date(e.date);
        return expenseDate.toDateString() === date.toDateString();
      });
      const dayTotal = dayExpenses.reduce((sum, e) => sum + Math.abs(e.amount), 0);
      last7Days.push({ date: date.toISOString(), value: dayTotal });
    }
    return last7Days;
  }, [expenses]);

  // Get top 3 categories for insights
  const topCategories = useMemo(() => {
    const categoryTotals = {};
    const totalExpenses = expenses.reduce((sum, e) => sum + Math.abs(e.amount), 0);
    
    expenses.forEach(expense => {
      const category = expense.category || 'Other';
      categoryTotals[category] = (categoryTotals[category] || 0) + Math.abs(expense.amount);
    });
    
    return Object.entries(categoryTotals)
      .map(([category, amount]) => ({
        category,
        amount,
        percentage: totalExpenses > 0 ? (amount / totalExpenses) * 100 : 0,
        trend: Math.random() * 20 - 10, // Mock trend for now
        budgetStatus: budgets.find(b => b.category === category.toLowerCase().replace(/\s+/g, '-'))
      }))
      .sort((a, b) => b.amount - a.amount)
      .slice(0, 3);
  }, [expenses, budgets]);

  return (
    <div className="space-y-6">
      {/* Analytics Overview Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Savings Rate Widget */}
        <AnalyticsWidget
          title="Savings Rate"
          value={`${metrics.savingsRate}%`}
          subtitle="This month"
          icon={BanknotesIcon}
          color={metrics.savingsRate >= 20 ? 'green' : metrics.savingsRate >= 10 ? 'yellow' : 'red'}
          trend={{ percentage: Math.random() * 10 - 5 }} // Mock trend
          analyticsFilter={{ type: 'savings' }}
          onNavigateToAnalytics={onNavigateToAnalytics}
          compact={true}
        />

        {/* Budget Adherence Widget */}
        <AnalyticsWidget
          title="Budget Adherence"
          value={`${metrics.budgetAdherence}%`}
          subtitle="Overall performance"
          icon={ChartBarIcon}
          color={metrics.budgetAdherence >= 80 ? 'green' : metrics.budgetAdherence >= 60 ? 'yellow' : 'red'}
          trend={{ percentage: Math.random() * 15 - 7.5 }} // Mock trend
          analyticsFilter={{ type: 'budgets' }}
          onNavigateToAnalytics={onNavigateToAnalytics}
          compact={true}
        />

        {/* Top Category Widget */}
        <AnalyticsWidget
          title="Top Spending"
          value={formatCurrency(metrics.topCategory.amount)}
          subtitle={metrics.topCategory.category}
          icon={TagIcon}
          color="blue"
          trend={{ percentage: metrics.spendingTrend }}
          analyticsFilter={{ category: metrics.topCategory.category }}
          onNavigateToAnalytics={onNavigateToAnalytics}
          compact={true}
        />
      </div>

      {/* Charts and Insights Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Spending Trend Mini Chart */}
        <MiniChartWidget
          title="7-Day Spending Trend"
          data={spendingTrendData}
          chartType="line"
          height={80}
          analyticsFilter={{ dateRange: 'WEEK' }}
          onNavigateToAnalytics={onNavigateToAnalytics}
        />

        {/* Quick Financial Health */}
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700 transition-base interactive-card hover-glow">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium text-gray-900 dark:text-white">
              Financial Health
            </h3>
            <button
              onClick={() => onNavigateToAnalytics && onNavigateToAnalytics('/analytics')}
              className="p-1 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 rounded transition-colors"
              title="View full analytics"
            >
              <ArrowTrendingUpIcon className="h-4 w-4" />
            </button>
          </div>
          
          <div className="space-y-3">
            {/* Net Income Status */}
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-400">Net Income</span>
              <span className={`text-sm font-medium ${
                metrics.netIncome >= 0 ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'
              }`}>
                {formatCurrency(metrics.netIncome)}
              </span>
            </div>
            
            {/* Expense Ratio */}
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-400">Expense Ratio</span>
              <span className="text-sm font-medium text-gray-900 dark:text-white">
                {metrics.totalIncome > 0 ? Math.round((metrics.totalExpenses / metrics.totalIncome) * 100) : 0}%
              </span>
            </div>
            
            {/* Budget Status */}
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-400">Budget Status</span>
              <span className={`text-sm font-medium ${
                metrics.budgetAdherence >= 80 ? 'text-green-600 dark:text-green-400' : 
                metrics.budgetAdherence >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 
                'text-red-600 dark:text-red-400'
              }`}>
                {metrics.budgetAdherence >= 80 ? 'Excellent' : 
                 metrics.budgetAdherence >= 60 ? 'Good' : 'Needs Attention'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Category Insights */}
      {topCategories.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Top Spending Categories
            </h3>
            <button
              onClick={() => onNavigateToAnalytics && onNavigateToAnalytics('/analytics?type=categories')}
              className="text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium transition-colors"
            >
              View All Categories →
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {topCategories.map((category, index) => (
              <CategoryInsightWidget
                key={category.category}
                category={category.category}
                amount={category.amount}
                percentage={category.percentage}
                trend={category.trend}
                budgetStatus={category.budgetStatus}
                onNavigateToAnalytics={onNavigateToAnalytics}
              />
            ))}
          </div>
        </div>
      )}

      {/* Quick Actions */}
      <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 p-4 rounded-lg border border-blue-200 dark:border-blue-800">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-blue-900 dark:text-blue-100">
              Get Deeper Insights
            </h3>
            <p className="text-xs text-blue-700 dark:text-blue-300 mt-1">
              Explore detailed analytics to optimize your financial health
            </p>
          </div>
          <button
            onClick={() => onNavigateToAnalytics && onNavigateToAnalytics('/analytics')}
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            View Analytics
          </button>
        </div>
      </div>
    </div>
  );
});

DashboardAnalytics.displayName = 'DashboardAnalytics';

export default DashboardAnalytics;
