import React, { memo } from 'react';
import {
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  EyeIcon
} from '@heroicons/react/24/outline';
import { useCurrency } from '../../context/CurrencyContext';
import { useTheme } from '../../context/ThemeContext';
import CategoryIcon from '../ui/CategoryIcon';
import { getCategoryColors } from '../../utils/categoryConfig';

const BudgetProgressWidget = memo(({
  budgets = [],
  expenses = [],
  isLoading = false,
  onViewAll,
  onBudgetClick,
  maxDisplay = 4,
  prioritizeBySpending = true
}) => {
  const { formatAmount } = useCurrency();
  const { isDark } = useTheme();

  // Calculate budget progress
  const budgetProgress = budgets.map(budget => {
    // Use budget.amount as the limit (budget schema uses 'amount' field)
    const budgetLimit = budget.amount || 0;

    // Use the spent amount from database (already calculated by backend)
    // If not available, calculate from current month expenses
    let spent = budget.spent || 0;

    // If database spent is 0, try calculating from current month expenses as fallback
    if (spent === 0) {
      const categoryExpenses = expenses.filter(expense =>
        expense.category === budget.category &&
        new Date(expense.date).getMonth() === new Date().getMonth() &&
        new Date(expense.date).getFullYear() === new Date().getFullYear()
      );
      spent = categoryExpenses.reduce((sum, expense) => sum + expense.amount, 0);
    }

    const percentage = budgetLimit > 0 ? (spent / budgetLimit) * 100 : 0;
    const remaining = Math.max(0, budgetLimit - spent);



    return {
      ...budget,
      limit: budgetLimit, // Add limit field for compatibility
      spent,
      percentage: Math.min(percentage, 100),
      remaining,
      status: percentage >= 100 ? 'exceeded' : percentage >= 80 ? 'warning' : 'good'
    };
  });

  // Smart filtering and sorting logic
  const getFilteredBudgets = () => {
    if (!prioritizeBySpending) {
      return budgetProgress.slice(0, maxDisplay);
    }

    // Sort by priority:
    // 1. Highest spending percentage first (closest to/over limit)
    // 2. Then by highest absolute spending amount
    // 3. Filter out budgets with 0 spending unless there are very few budgets
    const activeBudgets = budgetProgress.filter(budget => budget.spent > 0);
    const inactiveBudgets = budgetProgress.filter(budget => budget.spent === 0);

    const sortedActiveBudgets = activeBudgets.sort((a, b) => {
      // First priority: spending percentage (descending)
      if (Math.abs(a.percentage - b.percentage) > 1) {
        return b.percentage - a.percentage;
      }
      // Second priority: absolute spending amount (descending)
      return b.spent - a.spent;
    });

    // Include inactive budgets only if we need to fill up to maxDisplay
    const budgetsToShow = sortedActiveBudgets.length >= maxDisplay
      ? sortedActiveBudgets.slice(0, maxDisplay)
      : [
          ...sortedActiveBudgets,
          ...inactiveBudgets
            .sort((a, b) => (b.limit || b.amount) - (a.limit || a.amount))
            .slice(0, maxDisplay - sortedActiveBudgets.length)
        ];

    return budgetsToShow;
  };

  const topBudgets = getFilteredBudgets();
  const hasMoreBudgets = budgets.length > topBudgets.length;

  const getStatusColor = (status, category = null) => {
    // Get category colors for the progress bar
    const categoryColors = category ? getCategoryColors(category, isDark) : null;

    switch (status) {
      case 'exceeded':
        return {
          bg: 'bg-red-50 dark:bg-red-900/20',
          text: 'text-red-600 dark:text-red-400',
          bar: 'bg-red-500',
          barColor: isDark ? '#B91C1C' : '#EF4444', // Even darker red for dark mode
          icon: ExclamationTriangleIcon
        };
      case 'warning':
        return {
          bg: 'bg-yellow-50 dark:bg-yellow-900/20',
          text: 'text-yellow-600 dark:text-yellow-400',
          bar: 'bg-yellow-500',
          barColor: isDark ? '#B45309' : '#F59E0B', // Even darker yellow for dark mode
          icon: ClockIcon
        };
      default:
        return {
          bg: categoryColors ? '' : 'bg-green-50 dark:bg-green-900/20',
          text: categoryColors ? '' : 'text-green-600 dark:text-green-400',
          bar: categoryColors ? '' : 'bg-green-500',
          barColor: categoryColors ? categoryColors.primary : (isDark ? '#047857' : '#10B981'),
          icon: CheckCircleIcon
        };
    }
  };

  if (isLoading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-gray-100 dark:bg-gray-700 rounded-lg animate-pulse">
              <div className="h-5 w-5 bg-gray-300 dark:bg-gray-600 rounded"></div>
            </div>
            <div>
              <div className="h-5 w-32 bg-gray-300 dark:bg-gray-600 rounded animate-pulse"></div>
              <div className="h-4 w-24 bg-gray-200 dark:bg-gray-700 rounded animate-pulse mt-1"></div>
            </div>
          </div>
        </div>
        
        <div className="space-y-4">
          {[...Array(3)].map((_, index) => (
            <div key={index} className="space-y-2">
              <div className="flex justify-between">
                <div className="h-4 w-20 bg-gray-300 dark:bg-gray-600 rounded animate-pulse"></div>
                <div className="h-4 w-16 bg-gray-300 dark:bg-gray-600 rounded animate-pulse"></div>
              </div>
              <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full animate-pulse"></div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
      {/* Header */}
      <div className="p-5 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-blue-100 dark:bg-blue-900/50 rounded-lg">
              <ChartBarIcon className="h-5 w-5 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Budget Progress
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Current month spending vs budgets
              </p>
            </div>
          </div>

          {onViewAll && topBudgets.length > 0 && (
            <button
              onClick={onViewAll}
              className="flex items-center space-x-1 text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors font-medium"
            >
              <EyeIcon className="h-4 w-4" />
              <span>{hasMoreBudgets ? `View All (${budgets.length})` : 'View All'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Budget Progress List */}
      <div className="p-5">
        {topBudgets.length === 0 ? (
          <div className="text-center py-6">
            <ChartBarIcon className="h-12 w-12 text-gray-400 dark:text-gray-500 mx-auto mb-3" />
            <p className="text-gray-500 dark:text-gray-400 text-sm font-medium">
              No budgets set up
            </p>
            <p className="text-gray-400 dark:text-gray-500 text-xs mt-1">
              Create budgets to track your spending
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {topBudgets.map((budget, index) => {
              const statusColors = getStatusColor(budget.status, budget.category);
              const StatusIcon = statusColors.icon;
              const categoryColors = getCategoryColors(budget.category, isDark);

              return (
                <div
                  key={budget._id || budget.id || index}
                  onClick={() => onBudgetClick?.(budget)}
                  className={`p-4 rounded-lg border transition-all duration-200 ${
                    onBudgetClick
                      ? 'hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer hover:scale-[1.02]'
                      : ''
                  } border-gray-200 dark:border-gray-700`}
                  style={{
                    backgroundColor: budget.status === 'good'
                      ? categoryColors.secondary
                      : statusColors.bg.includes('bg-') ? undefined : statusColors.bg,
                    borderColor: budget.status === 'good'
                      ? categoryColors.border
                      : undefined
                  }}
                >
                  {/* Budget Header */}
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <CategoryIcon
                        category={budget.category}
                        size="sm"
                        variant="soft"
                        isDark={isDark}
                      />
                      <div className="flex items-center space-x-2">
                        <StatusIcon className={`h-4 w-4 ${
                          budget.status === 'good' ? '' : statusColors.text
                        }`}
                        style={{
                          color: budget.status === 'good' ? categoryColors.text : undefined
                        }}
                        />
                        <span className="font-medium text-gray-900 dark:text-white">
                          {budget.category || budget.name}
                        </span>
                      </div>
                    </div>
                    <span className={`text-sm font-medium ${
                      budget.status === 'good' ? '' : statusColors.text
                    }`}
                    style={{
                      color: budget.status === 'good' ? categoryColors.text : undefined
                    }}
                    >
                      {budget.percentage.toFixed(1)}%
                    </span>
                  </div>

                  {/* Progress Bar */}
                  <div className="mb-3">
                    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2.5">
                      <div
                        className="h-2.5 rounded-full transition-all duration-300"
                        style={{
                          width: `${Math.min(budget.percentage, 100)}%`,
                          backgroundColor: statusColors.barColor
                        }}
                      ></div>
                    </div>
                  </div>

                  {/* Budget Details */}
                  <div className="flex items-center justify-between text-sm">
                    <div className="text-gray-600 dark:text-gray-400">
                      <span className="font-medium">
                        {formatAmount(budget.spent, { showSymbol: true })}
                      </span>
                      <span className="mx-1">of</span>
                      <span>
                        {formatAmount(budget.limit || budget.amount, { showSymbol: true })}
                      </span>
                    </div>
                    
                    <div className={`font-medium ${
                      budget.status === 'exceeded' 
                        ? 'text-red-600 dark:text-red-400' 
                        : 'text-gray-600 dark:text-gray-400'
                    }`}>
                      {budget.status === 'exceeded'
                        ? `Over by ${formatAmount(budget.spent - (budget.limit || budget.amount), { showSymbol: true })}`
                        : `${formatAmount(budget.remaining, { showSymbol: true })} left`
                      }
                    </div>
                  </div>

                  {/* Warning message for exceeded budgets */}
                  {budget.status === 'exceeded' && (
                    <div className="mt-2 text-xs text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 p-2 rounded">
                      ⚠️ Budget exceeded! Consider reviewing your spending in this category.
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Footer */}
      {topBudgets.length > 0 && (
        <div className="px-6 py-3 bg-gray-50 dark:bg-gray-700/50 border-t border-gray-200 dark:border-gray-700 rounded-b-lg">
          <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
            <span>
              {topBudgets.filter(b => b.status === 'exceeded').length} exceeded • {' '}
              {topBudgets.filter(b => b.status === 'warning').length} near limit • {' '}
              {topBudgets.filter(b => b.status === 'good').length} on track
              {hasMoreBudgets && (
                <span className="ml-2 text-blue-600 dark:text-blue-400">
                  • {budgets.length - topBudgets.length} more
                </span>
              )}
            </span>
            {onViewAll && (
              <button
                onClick={onViewAll}
                className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
              >
                {hasMoreBudgets ? 'View All →' : 'Manage →'}
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
});

BudgetProgressWidget.displayName = 'BudgetProgressWidget';

export default BudgetProgressWidget;
