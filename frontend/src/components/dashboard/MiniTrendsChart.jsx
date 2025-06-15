import React, { memo, useMemo } from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  ResponsiveContainer,
  Tooltip
} from 'recharts';
import { ChartBarIcon, ArrowTrendingUpIcon, ArrowTrendingDownIcon } from '@heroicons/react/24/outline';
import { useTheme } from '../../context/ThemeContext';
import { useCurrency } from '../../context/CurrencyContext';
import { ChartErrorBoundary } from '../ErrorBoundary';

const MiniTrendsChart = memo(({ 
  expenses = [], 
  income = [],
  isLoading = false,
  onViewAnalytics 
}) => {
  const { isDark } = useTheme();
  const { formatAmount } = useCurrency();

  // Process data for the last 7 days
  const chartData = useMemo(() => {
    const last7Days = [];
    const today = new Date();
    
    for (let i = 6; i >= 0; i--) {
      const date = new Date(today);
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      
      const dayExpenses = expenses
        .filter(expense => expense.date.startsWith(dateStr))
        .reduce((sum, expense) => sum + expense.amount, 0);
      
      const dayIncome = income
        .filter(inc => inc.date.startsWith(dateStr))
        .reduce((sum, inc) => sum + inc.amount, 0);
      
      last7Days.push({
        date: dateStr,
        day: date.toLocaleDateString('en-IN', { weekday: 'short' }),
        expenses: dayExpenses,
        income: dayIncome,
        net: dayIncome - dayExpenses
      });
    }
    
    return last7Days;
  }, [expenses, income]);

  // Calculate trends
  const trends = useMemo(() => {
    if (chartData.length < 2) return { expenses: 0, income: 0, net: 0 };
    
    const recent = chartData.slice(-3).reduce((sum, day) => ({
      expenses: sum.expenses + day.expenses,
      income: sum.income + day.income,
      net: sum.net + day.net
    }), { expenses: 0, income: 0, net: 0 });
    
    const previous = chartData.slice(0, 3).reduce((sum, day) => ({
      expenses: sum.expenses + day.expenses,
      income: sum.income + day.income,
      net: sum.net + day.net
    }), { expenses: 0, income: 0, net: 0 });
    
    return {
      expenses: previous.expenses > 0 ? ((recent.expenses - previous.expenses) / previous.expenses) * 100 : 0,
      income: previous.income > 0 ? ((recent.income - previous.income) / previous.income) * 100 : 0,
      net: previous.net !== 0 ? ((recent.net - previous.net) / Math.abs(previous.net)) * 100 : 0
    };
  }, [chartData]);

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="bg-white dark:bg-gray-800 p-3 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
          <p className="text-sm font-medium text-gray-900 dark:text-white mb-2">
            {new Date(data.date).toLocaleDateString('en-IN', { 
              weekday: 'long', 
              month: 'short', 
              day: 'numeric' 
            })}
          </p>
          <div className="space-y-1 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-green-600 dark:text-green-400">Income:</span>
              <span className="font-medium text-gray-900 dark:text-white">{formatAmount(data.income, { showSymbol: true })}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-red-600 dark:text-red-400">Expenses:</span>
              <span className="font-medium text-gray-900 dark:text-white">{formatAmount(data.expenses, { showSymbol: true })}</span>
            </div>
            <div className="flex items-center justify-between border-t border-gray-200 dark:border-gray-600 pt-1">
              <span className="text-gray-600 dark:text-gray-300">Net:</span>
              <span className={`font-medium ${
                data.net >= 0
                  ? 'text-green-600 dark:text-green-400'
                  : 'text-red-600 dark:text-red-400'
              }`}>
                {formatAmount(data.net, { showSymbol: true })}
              </span>
            </div>
          </div>
        </div>
      );
    }
    return null;
  };

  const getTrendIcon = (trend) => {
    if (Math.abs(trend) < 1) return null;
    return trend > 0 ? ArrowTrendingUpIcon : ArrowTrendingDownIcon;
  };

  const getTrendColor = (trend, isExpense = false) => {
    if (Math.abs(trend) < 1) return 'text-gray-500 dark:text-gray-400';
    
    // For expenses, negative trend (decrease) is good
    if (isExpense) {
      return trend < 0 
        ? 'text-green-600 dark:text-green-400' 
        : 'text-red-600 dark:text-red-400';
    }
    
    // For income, positive trend is good
    return trend > 0 
      ? 'text-green-600 dark:text-green-400' 
      : 'text-red-600 dark:text-red-400';
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
        <div className="h-48 bg-gray-100 dark:bg-gray-700 rounded animate-pulse"></div>
      </div>
    );
  }

  return (
    <ChartErrorBoundary>
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700">
        {/* Header */}
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-blue-100 dark:bg-blue-900/50 rounded-lg">
                <ChartBarIcon className="h-5 w-5 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                  7-Day Spending Trend
                </h3>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Daily income vs expenses
                </p>
              </div>
            </div>
            
            {onViewAnalytics && (
              <button
                onClick={onViewAnalytics}
                className="text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
              >
                View Analytics →
              </button>
            )}
          </div>
        </div>

        {/* Chart */}
        <div className="p-6">
          <div className="h-48 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData} margin={{ top: 5, right: 5, left: 5, bottom: 5 }}>
                <XAxis 
                  dataKey="day" 
                  axisLine={false}
                  tickLine={false}
                  tick={{ 
                    fontSize: 12, 
                    fill: isDark ? '#9CA3AF' : '#6B7280' 
                  }}
                />
                <YAxis 
                  hide 
                />
                <Tooltip content={<CustomTooltip />} />
                <Line
                  type="monotone"
                  dataKey="income"
                  stroke="#10B981"
                  strokeWidth={2}
                  dot={{ fill: '#10B981', strokeWidth: 2, r: 3 }}
                  activeDot={{ r: 5, stroke: '#10B981', strokeWidth: 2 }}
                />
                <Line
                  type="monotone"
                  dataKey="expenses"
                  stroke="#EF4444"
                  strokeWidth={2}
                  dot={{ fill: '#EF4444', strokeWidth: 2, r: 3 }}
                  activeDot={{ r: 5, stroke: '#EF4444', strokeWidth: 2 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Trend Summary */}
        <div className="px-6 py-3 bg-gray-50 dark:bg-gray-700/50 border-t border-gray-200 dark:border-gray-700 rounded-b-lg">
          <div className="grid grid-cols-2 gap-4 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-gray-600 dark:text-gray-300">Income trend:</span>
              <div className={`flex items-center space-x-1 ${getTrendColor(trends.income)}`}>
                {getTrendIcon(trends.income) && React.createElement(getTrendIcon(trends.income), { className: "h-3 w-3" })}
                <span className="font-medium text-gray-900 dark:text-white">
                  {Math.abs(trends.income) < 1 ? 'Stable' : `${trends.income > 0 ? '+' : ''}${trends.income.toFixed(1)}%`}
                </span>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-gray-600 dark:text-gray-300">Expense trend:</span>
              <div className={`flex items-center space-x-1 ${getTrendColor(trends.expenses, true)}`}>
                {getTrendIcon(trends.expenses) && React.createElement(getTrendIcon(trends.expenses), { className: "h-3 w-3" })}
                <span className="font-medium text-gray-900 dark:text-white">
                  {Math.abs(trends.expenses) < 1 ? 'Stable' : `${trends.expenses > 0 ? '+' : ''}${trends.expenses.toFixed(1)}%`}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </ChartErrorBoundary>
  );
});

MiniTrendsChart.displayName = 'MiniTrendsChart';

export default MiniTrendsChart;
