import React, { memo, useMemo } from 'react';
import { 
  CheckCircleIcon, 
  ExclamationTriangleIcon, 
  XCircleIcon 
} from '@heroicons/react/24/outline';
import { formatCurrency } from '../../utils/analyticsHelpers';

const BudgetPerformance = memo(({ budgets }) => {
  // Process budget data for performance analysis
  const budgetAnalysis = useMemo(() => {
    if (!budgets || budgets.length === 0) return { onTrack: 0, warning: 0, exceeded: 0, items: [] };

    const items = budgets.map(budget => {
      const percentage = (budget.spent / budget.amount) * 100;
      const remaining = budget.amount - budget.spent;
      
      let status, color, icon;
      if (percentage >= 100) {
        status = 'exceeded';
        color = 'red';
        icon = XCircleIcon;
      } else if (percentage >= (budget.alertThreshold || 80)) {
        status = 'warning';
        color = 'yellow';
        icon = ExclamationTriangleIcon;
      } else {
        status = 'on-track';
        color = 'green';
        icon = CheckCircleIcon;
      }

      return {
        ...budget,
        percentage: Math.min(percentage, 100),
        remaining,
        status,
        color,
        icon
      };
    });

    const summary = items.reduce(
      (acc, item) => {
        acc[item.status]++;
        return acc;
      },
      { onTrack: 0, warning: 0, exceeded: 0 }
    );

    return { ...summary, items };
  }, [budgets]);

  // Color classes for different statuses
  const statusColors = {
    'on-track': {
      bg: 'bg-green-100 dark:bg-green-900/20',
      text: 'text-green-800 dark:text-green-300',
      icon: 'text-green-600 dark:text-green-400',
      progress: 'bg-green-500'
    },
    warning: {
      bg: 'bg-yellow-100 dark:bg-yellow-900/20',
      text: 'text-yellow-800 dark:text-yellow-300',
      icon: 'text-yellow-600 dark:text-yellow-400',
      progress: 'bg-yellow-500'
    },
    exceeded: {
      bg: 'bg-red-100 dark:bg-red-900/20',
      text: 'text-red-800 dark:text-red-300',
      icon: 'text-red-600 dark:text-red-400',
      progress: 'bg-red-500'
    }
  };

  // Empty state
  if (!budgets || budgets.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow border border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Budget Performance
        </h3>
        <div className="text-center py-8">
          <div className="w-16 h-16 mx-auto mb-4 bg-gray-100 dark:bg-gray-700 rounded-full flex items-center justify-center">
            <svg className="w-8 h-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <p className="text-gray-500 dark:text-gray-400">No budgets available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow border border-gray-200 dark:border-gray-700 transition-base interactive-card">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Budget Performance
        </h3>
        <div className="flex items-center space-x-4 text-sm">
          <div className="flex items-center space-x-1">
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
            <span className="text-gray-600 dark:text-gray-400">{budgetAnalysis.onTrack}</span>
          </div>
          <div className="flex items-center space-x-1">
            <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
            <span className="text-gray-600 dark:text-gray-400">{budgetAnalysis.warning}</span>
          </div>
          <div className="flex items-center space-x-1">
            <div className="w-3 h-3 bg-red-500 rounded-full"></div>
            <span className="text-gray-600 dark:text-gray-400">{budgetAnalysis.exceeded}</span>
          </div>
        </div>
      </div>

      {/* Budget Items */}
      <div className="space-y-4">
        {budgetAnalysis.items.map((budget) => {
          const Icon = budget.icon;
          const colors = statusColors[budget.status];
          
          return (
            <div
              key={budget._id}
              className="group hover:bg-gray-50 dark:hover:bg-gray-700/50 p-4 rounded-lg transition-all duration-200"
            >
              {/* Budget Header */}
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center space-x-3">
                  <div className={`p-2 rounded-lg ${colors.bg}`}>
                    <Icon className={`h-5 w-5 ${colors.icon}`} />
                  </div>
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                      {budget.name}
                    </h4>
                    <p className="text-xs text-gray-500 dark:text-gray-400 capitalize">
                      {budget.period} budget
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-sm font-semibold text-gray-900 dark:text-white">
                    {formatCurrency(budget.spent)} / {formatCurrency(budget.amount)}
                  </p>
                  <p className={`text-xs font-medium ${colors.text}`}>
                    {budget.percentage.toFixed(1)}% used
                  </p>
                </div>
              </div>

              {/* Progress Bar */}
              <div className="mb-3">
                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full transition-all duration-300 ease-out ${colors.progress}`}
                    style={{ width: `${budget.percentage}%` }}
                  />
                </div>
              </div>

              {/* Budget Details */}
              <div className="flex justify-between items-center text-xs text-gray-500 dark:text-gray-400">
                <span>
                  {budget.remaining >= 0 
                    ? `${formatCurrency(budget.remaining)} remaining`
                    : `${formatCurrency(Math.abs(budget.remaining))} over budget`
                  }
                </span>
                <span className={`px-2 py-1 rounded-full ${colors.bg} ${colors.text} font-medium`}>
                  {budget.status === 'on-track' && 'On Track'}
                  {budget.status === 'warning' && 'Near Limit'}
                  {budget.status === 'exceeded' && 'Over Budget'}
                </span>
              </div>

              {/* Alert Threshold Indicator */}
              {budget.status !== 'exceeded' && (
                <div className="mt-2 text-xs text-gray-400 dark:text-gray-500">
                  Alert at {budget.alertThreshold || 80}% ({formatCurrency((budget.amount * (budget.alertThreshold || 80)) / 100)})
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Summary */}
      <div className="mt-6 pt-4 border-t border-gray-200 dark:border-gray-700">
        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <p className="text-2xl font-bold text-green-600 dark:text-green-400">
              {budgetAnalysis.onTrack}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400">On Track</p>
          </div>
          <div>
            <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
              {budgetAnalysis.warning}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400">Warning</p>
          </div>
          <div>
            <p className="text-2xl font-bold text-red-600 dark:text-red-400">
              {budgetAnalysis.exceeded}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400">Exceeded</p>
          </div>
        </div>
      </div>
    </div>
  );
});

BudgetPerformance.displayName = 'BudgetPerformance';

export default BudgetPerformance;
