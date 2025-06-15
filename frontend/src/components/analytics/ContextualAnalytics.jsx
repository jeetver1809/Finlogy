import React, { memo, useMemo } from 'react';
import { 
  ChartBarIcon, 
  TrendingUpIcon as ArrowTrendingUpIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline';
import { formatCurrency } from '../../utils/analyticsHelpers';
import { createAnalyticsUrl } from '../../utils/analyticsIntegration';

// Expense Page Analytics Integration
const ExpenseAnalyticsPanel = memo(({ 
  expenses = [], 
  budgets = [], 
  selectedCategory = null,
  onNavigateToAnalytics 
}) => {
  
  const analytics = useMemo(() => {
    const filteredExpenses = selectedCategory 
      ? expenses.filter(e => e.category === selectedCategory)
      : expenses;
    
    // Category spending analysis
    const categoryTotals = {};
    filteredExpenses.forEach(expense => {
      const category = expense.category || 'Other';
      categoryTotals[category] = (categoryTotals[category] || 0) + Math.abs(expense.amount);
    });
    
    const sortedCategories = Object.entries(categoryTotals)
      .map(([category, amount]) => ({ category, amount }))
      .sort((a, b) => b.amount - a.amount);
    
    // Budget impact analysis
    const budgetImpacts = budgets.map(budget => {
      const categoryExpenses = expenses.filter(e => 
        e.category === budget.category || 
        e.category === budget.name.toLowerCase().replace(/\s+/g, '-')
      );
      const spent = categoryExpenses.reduce((sum, e) => sum + Math.abs(e.amount), 0);
      const percentage = (spent / budget.amount) * 100;
      
      return {
        ...budget,
        spent,
        percentage,
        remaining: budget.amount - spent,
        status: percentage >= 100 ? 'exceeded' : percentage >= 80 ? 'warning' : 'on-track'
      };
    }).filter(b => b.spent > 0);
    
    return {
      categoryTotals: sortedCategories,
      budgetImpacts,
      totalSpent: filteredExpenses.reduce((sum, e) => sum + Math.abs(e.amount), 0),
      transactionCount: filteredExpenses.length
    };
  }, [expenses, budgets, selectedCategory]);

  const handleViewAnalytics = (filter = {}) => {
    if (onNavigateToAnalytics) {
      const url = createAnalyticsUrl({ ...filter, type: 'expenses' });
      onNavigateToAnalytics(url);
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Expense Analytics
        </h3>
        <button
          onClick={() => handleViewAnalytics()}
          className="text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium transition-colors"
        >
          View Full Analytics →
        </button>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className="text-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {formatCurrency(analytics.totalSpent)}
          </p>
          <p className="text-sm text-gray-600 dark:text-gray-400">Total Spent</p>
        </div>
        <div className="text-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {analytics.transactionCount}
          </p>
          <p className="text-sm text-gray-600 dark:text-gray-400">Transactions</p>
        </div>
      </div>

      {/* Budget Impact Alerts */}
      {analytics.budgetImpacts.length > 0 && (
        <div className="mb-6">
          <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">
            Budget Impact
          </h4>
          <div className="space-y-2">
            {analytics.budgetImpacts.slice(0, 3).map(budget => (
              <div 
                key={budget._id}
                className={`p-3 rounded-lg border ${
                  budget.status === 'exceeded' ? 'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-900/20' :
                  budget.status === 'warning' ? 'border-yellow-200 bg-yellow-50 dark:border-yellow-800 dark:bg-yellow-900/20' :
                  'border-green-200 bg-green-50 dark:border-green-800 dark:bg-green-900/20'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    {budget.status === 'exceeded' ? (
                      <ExclamationTriangleIcon className="h-4 w-4 text-red-600 dark:text-red-400" />
                    ) : budget.status === 'warning' ? (
                      <ExclamationTriangleIcon className="h-4 w-4 text-yellow-600 dark:text-yellow-400" />
                    ) : (
                      <InformationCircleIcon className="h-4 w-4 text-green-600 dark:text-green-400" />
                    )}
                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                      {budget.name}
                    </span>
                  </div>
                  <span className="text-sm text-gray-600 dark:text-gray-400">
                    {budget.percentage.toFixed(1)}%
                  </span>
                </div>
                <div className="mt-2">
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full ${
                        budget.status === 'exceeded' ? 'bg-red-500' :
                        budget.status === 'warning' ? 'bg-yellow-500' : 'bg-green-500'
                      }`}
                      style={{ width: `${Math.min(budget.percentage, 100)}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Top Categories */}
      <div>
        <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">
          Top Categories
        </h4>
        <div className="space-y-2">
          {analytics.categoryTotals.slice(0, 5).map((category, index) => (
            <div 
              key={category.category}
              className="flex items-center justify-between p-2 hover:bg-gray-50 dark:hover:bg-gray-700 rounded cursor-pointer transition-colors"
              onClick={() => handleViewAnalytics({ category: category.category })}
            >
              <div className="flex items-center space-x-3">
                <div className="w-2 h-2 bg-blue-500 rounded-full" />
                <span className="text-sm text-gray-900 dark:text-white">
                  {category.category}
                </span>
              </div>
              <span className="text-sm font-medium text-gray-900 dark:text-white">
                {formatCurrency(category.amount)}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
});

// Income Page Analytics Integration
const IncomeAnalyticsPanel = memo(({ 
  income = [], 
  expenses = [],
  onNavigateToAnalytics 
}) => {
  
  const analytics = useMemo(() => {
    const totalIncome = income.reduce((sum, i) => sum + i.amount, 0);
    const totalExpenses = expenses.reduce((sum, e) => sum + Math.abs(e.amount), 0);
    const netIncome = totalIncome - totalExpenses;
    const savingsRate = totalIncome > 0 ? (netIncome / totalIncome) * 100 : 0;
    
    // Income sources breakdown
    const sourceBreakdown = income.reduce((acc, inc) => {
      const source = inc.source || 'Other';
      acc[source] = (acc[source] || 0) + inc.amount;
      return acc;
    }, {});
    
    const sortedSources = Object.entries(sourceBreakdown)
      .map(([source, amount]) => ({ source, amount }))
      .sort((a, b) => b.amount - a.amount);
    
    return {
      totalIncome,
      totalExpenses,
      netIncome,
      savingsRate,
      sourceBreakdown: sortedSources,
      incomeCount: income.length
    };
  }, [income, expenses]);

  const handleViewAnalytics = (filter = {}) => {
    if (onNavigateToAnalytics) {
      const url = createAnalyticsUrl({ ...filter, type: 'income' });
      onNavigateToAnalytics(url);
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Income Analytics
        </h3>
        <button
          onClick={() => handleViewAnalytics()}
          className="text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium transition-colors"
        >
          View Full Analytics →
        </button>
      </div>

      {/* Income vs Expenses Correlation */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="text-center p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
          <p className="text-xl font-bold text-green-700 dark:text-green-300">
            {formatCurrency(analytics.totalIncome)}
          </p>
          <p className="text-sm text-green-600 dark:text-green-400">Total Income</p>
        </div>
        <div className="text-center p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
          <p className="text-xl font-bold text-red-700 dark:text-red-300">
            {formatCurrency(analytics.totalExpenses)}
          </p>
          <p className="text-sm text-red-600 dark:text-red-400">Total Expenses</p>
        </div>
        <div className={`text-center p-3 rounded-lg ${
          analytics.netIncome >= 0 
            ? 'bg-blue-50 dark:bg-blue-900/20' 
            : 'bg-red-50 dark:bg-red-900/20'
        }`}>
          <p className={`text-xl font-bold ${
            analytics.netIncome >= 0 
              ? 'text-blue-700 dark:text-blue-300' 
              : 'text-red-700 dark:text-red-300'
          }`}>
            {formatCurrency(analytics.netIncome)}
          </p>
          <p className={`text-sm ${
            analytics.netIncome >= 0 
              ? 'text-blue-600 dark:text-blue-400' 
              : 'text-red-600 dark:text-red-400'
          }`}>
            Net Income
          </p>
        </div>
      </div>

      {/* Savings Rate */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-gray-900 dark:text-white">
            Savings Rate
          </span>
          <span className={`text-sm font-bold ${
            analytics.savingsRate >= 20 ? 'text-green-600 dark:text-green-400' :
            analytics.savingsRate >= 10 ? 'text-yellow-600 dark:text-yellow-400' :
            'text-red-600 dark:text-red-400'
          }`}>
            {analytics.savingsRate.toFixed(1)}%
          </span>
        </div>
        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
          <div
            className={`h-3 rounded-full ${
              analytics.savingsRate >= 20 ? 'bg-green-500' :
              analytics.savingsRate >= 10 ? 'bg-yellow-500' : 'bg-red-500'
            }`}
            style={{ width: `${Math.min(analytics.savingsRate, 100)}%` }}
          />
        </div>
      </div>

      {/* Income Sources */}
      <div>
        <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">
          Income Sources
        </h4>
        <div className="space-y-2">
          {analytics.sourceBreakdown.map((source, index) => (
            <div 
              key={source.source}
              className="flex items-center justify-between p-2 hover:bg-gray-50 dark:hover:bg-gray-700 rounded cursor-pointer transition-colors"
              onClick={() => handleViewAnalytics({ source: source.source })}
            >
              <div className="flex items-center space-x-3">
                <div className="w-2 h-2 bg-green-500 rounded-full" />
                <span className="text-sm text-gray-900 dark:text-white">
                  {source.source}
                </span>
              </div>
              <span className="text-sm font-medium text-gray-900 dark:text-white">
                {formatCurrency(source.amount)}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
});

// Budget Page Analytics Integration
const BudgetAnalyticsPanel = memo(({ 
  budgets = [], 
  expenses = [],
  onNavigateToAnalytics 
}) => {
  
  const analytics = useMemo(() => {
    const budgetAnalysis = budgets.map(budget => {
      const categoryExpenses = expenses.filter(e => 
        e.category === budget.category || 
        e.category === budget.name.toLowerCase().replace(/\s+/g, '-')
      );
      
      const spent = categoryExpenses.reduce((sum, e) => sum + Math.abs(e.amount), 0);
      const percentage = (spent / budget.amount) * 100;
      const remaining = budget.amount - spent;
      
      let status = 'on-track';
      if (percentage >= 100) status = 'exceeded';
      else if (percentage >= (budget.alertThreshold || 80)) status = 'warning';
      
      return {
        ...budget,
        spent,
        percentage,
        remaining,
        status,
        recentTransactions: categoryExpenses.slice(0, 3)
      };
    });
    
    const statusCounts = budgetAnalysis.reduce((acc, budget) => {
      acc[budget.status] = (acc[budget.status] || 0) + 1;
      return acc;
    }, {});
    
    return {
      budgetAnalysis,
      statusCounts,
      totalBudgeted: budgets.reduce((sum, b) => sum + b.amount, 0),
      totalSpent: budgetAnalysis.reduce((sum, b) => sum + b.spent, 0)
    };
  }, [budgets, expenses]);

  const handleViewAnalytics = (filter = {}) => {
    if (onNavigateToAnalytics) {
      const url = createAnalyticsUrl({ ...filter, type: 'budgets' });
      onNavigateToAnalytics(url);
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Budget Performance
        </h3>
        <button
          onClick={() => handleViewAnalytics()}
          className="text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium transition-colors"
        >
          View Full Analytics →
        </button>
      </div>

      {/* Performance Summary */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="text-center p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
          <p className="text-xl font-bold text-green-700 dark:text-green-300">
            {analytics.statusCounts['on-track'] || 0}
          </p>
          <p className="text-sm text-green-600 dark:text-green-400">On Track</p>
        </div>
        <div className="text-center p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
          <p className="text-xl font-bold text-yellow-700 dark:text-yellow-300">
            {analytics.statusCounts.warning || 0}
          </p>
          <p className="text-sm text-yellow-600 dark:text-yellow-400">Warning</p>
        </div>
        <div className="text-center p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
          <p className="text-xl font-bold text-red-700 dark:text-red-300">
            {analytics.statusCounts.exceeded || 0}
          </p>
          <p className="text-sm text-red-600 dark:text-red-400">Exceeded</p>
        </div>
      </div>

      {/* Budget List with Performance */}
      <div className="space-y-3">
        {analytics.budgetAnalysis.slice(0, 5).map(budget => (
          <div 
            key={budget._id}
            className="p-3 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition-colors"
            onClick={() => handleViewAnalytics({ budget: budget._id })}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-900 dark:text-white">
                {budget.name}
              </span>
              <span className={`text-sm font-bold ${
                budget.status === 'exceeded' ? 'text-red-600 dark:text-red-400' :
                budget.status === 'warning' ? 'text-yellow-600 dark:text-yellow-400' :
                'text-green-600 dark:text-green-400'
              }`}>
                {budget.percentage.toFixed(1)}%
              </span>
            </div>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div
                className={`h-2 rounded-full ${
                  budget.status === 'exceeded' ? 'bg-red-500' :
                  budget.status === 'warning' ? 'bg-yellow-500' : 'bg-green-500'
                }`}
                style={{ width: `${Math.min(budget.percentage, 100)}%` }}
              />
            </div>
            <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400 mt-1">
              <span>{formatCurrency(budget.spent)} spent</span>
              <span>{formatCurrency(budget.remaining)} remaining</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
});

ExpenseAnalyticsPanel.displayName = 'ExpenseAnalyticsPanel';
IncomeAnalyticsPanel.displayName = 'IncomeAnalyticsPanel';
BudgetAnalyticsPanel.displayName = 'BudgetAnalyticsPanel';

export { ExpenseAnalyticsPanel, IncomeAnalyticsPanel, BudgetAnalyticsPanel };
