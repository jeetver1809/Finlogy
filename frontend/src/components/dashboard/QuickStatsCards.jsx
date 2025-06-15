import React, { memo } from 'react';
import {
  CurrencyDollarIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  BanknotesIcon,
  ChartBarIcon,
  CalendarIcon
} from '@heroicons/react/24/outline';
import { useCurrency } from '../../context/CurrencyContext';

const QuickStatsCards = memo(({ 
  totalBalance = 0,
  monthlyExpenses = 0,
  monthlyIncome = 0,
  savingsRate = 0,
  isLoading = false,
  previousMonth = {}
}) => {
  const { formatAmount } = useCurrency();

  // Calculate percentage changes
  const calculateChange = (current, previous) => {
    if (!previous || previous === 0) return 0;
    return ((current - previous) / previous) * 100;
  };

  const expenseChange = calculateChange(monthlyExpenses, previousMonth.expenses || 0);
  const incomeChange = calculateChange(monthlyIncome, previousMonth.income || 0);
  const balanceChange = calculateChange(totalBalance, previousMonth.balance || 0);

  const stats = [
    {
      id: 'balance',
      title: 'Total Balance',
      value: totalBalance,
      change: balanceChange,
      icon: BanknotesIcon,
      color: 'blue',
      bgColor: 'bg-blue-50 dark:bg-blue-900/20',
      iconColor: 'text-blue-600 dark:text-blue-400',
      description: 'Current account balance'
    },
    {
      id: 'income',
      title: 'This Month\'s Income',
      value: monthlyIncome,
      change: incomeChange,
      icon: ArrowTrendingUpIcon,
      color: 'green',
      bgColor: 'bg-green-50 dark:bg-green-900/20',
      iconColor: 'text-green-600 dark:text-green-400',
      description: 'Income for current month'
    },
    {
      id: 'expenses',
      title: 'This Month\'s Expenses',
      value: monthlyExpenses,
      change: expenseChange,
      icon: ArrowTrendingDownIcon,
      color: 'red',
      bgColor: 'bg-red-50 dark:bg-red-900/20',
      iconColor: 'text-red-600 dark:text-red-400',
      description: 'Expenses for current month'
    },
    {
      id: 'savings',
      title: 'Savings Rate',
      value: savingsRate,
      isPercentage: true,
      icon: ChartBarIcon,
      color: 'purple',
      bgColor: 'bg-purple-50 dark:bg-purple-900/20',
      iconColor: 'text-purple-600 dark:text-purple-400',
      description: 'Percentage of income saved'
    }
  ];

  const formatChangeValue = (change) => {
    if (change === 0) return '0%';
    const sign = change > 0 ? '+' : '';
    return `${sign}${change.toFixed(1)}%`;
  };

  const getChangeColor = (change, isExpense = false) => {
    if (change === 0) return 'text-gray-500 dark:text-gray-400';
    
    // For expenses, negative change (decrease) is good
    if (isExpense) {
      return change < 0 
        ? 'text-green-600 dark:text-green-400' 
        : 'text-red-600 dark:text-red-400';
    }
    
    // For income and balance, positive change is good
    return change > 0 
      ? 'text-green-600 dark:text-green-400' 
      : 'text-red-600 dark:text-red-400';
  };

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[...Array(4)].map((_, index) => (
          <div key={index} className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="p-2 bg-gray-200 dark:bg-gray-700 rounded-lg animate-pulse">
                <div className="h-6 w-6 bg-gray-300 dark:bg-gray-600 rounded"></div>
              </div>
              <div className="h-4 w-12 bg-gray-200 dark:bg-gray-700 rounded animate-pulse"></div>
            </div>
            <div className="space-y-2">
              <div className="h-8 w-24 bg-gray-200 dark:bg-gray-700 rounded animate-pulse"></div>
              <div className="h-4 w-32 bg-gray-200 dark:bg-gray-700 rounded animate-pulse"></div>
              <div className="h-3 w-28 bg-gray-200 dark:bg-gray-700 rounded animate-pulse"></div>
            </div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {stats.map((stat) => (
        <div
          key={stat.id}
          className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-6 interactive-card transition-base"
        >
          {/* Header */}
          <div className="flex items-center justify-between mb-4">
            <div className={`p-2 rounded-lg ${stat.bgColor}`}>
              <stat.icon className={`h-6 w-6 ${stat.iconColor}`} />
            </div>
            
            {/* Change indicator - only show if there's meaningful change data */}
            {stat.change !== undefined && stat.change !== 0 && (
              <div className={`text-sm font-medium ${getChangeColor(stat.change, stat.id === 'expenses')}`}>
                {formatChangeValue(stat.change)}
              </div>
            )}
          </div>

          {/* Value */}
          <div className="space-y-2">
            <div className="text-2xl font-bold text-gray-900 dark:text-white">
              {stat.isPercentage 
                ? `${stat.value.toFixed(1)}%`
                : formatAmount(stat.value, { showSymbol: true, minimumFractionDigits: 0 })
              }
            </div>
            
            <div className="text-sm font-medium text-gray-700 dark:text-gray-300">
              {stat.title}
            </div>
            
            <div className="text-xs text-gray-500 dark:text-gray-400">
              {stat.description}
            </div>
          </div>

          {/* Additional info for current month */}
          {(stat.id === 'income' || stat.id === 'expenses') && (
            <div className="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700">
              <div className="flex items-center text-xs text-gray-500 dark:text-gray-400">
                <CalendarIcon className="h-3 w-3 mr-1" />
                <span>
                  {new Date().toLocaleDateString('en-IN', { 
                    month: 'long', 
                    year: 'numeric' 
                  })}
                </span>
              </div>
            </div>
          )}

          {/* Savings rate additional info */}
          {stat.id === 'savings' && monthlyIncome > 0 && (
            <div className="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700">
              <div className="text-xs text-gray-500 dark:text-gray-400">
                Saved: {formatAmount(monthlyIncome - monthlyExpenses, { showSymbol: true })} this month
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
});

QuickStatsCards.displayName = 'QuickStatsCards';

export default QuickStatsCards;
