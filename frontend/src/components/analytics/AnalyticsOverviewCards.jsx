import React, { memo, useMemo } from 'react';
import {
  CurrencyDollarIcon,
  ArrowTrendingUpIcon,
  BanknotesIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline';
import { getTrendIndicator } from '../../utils/analyticsHelpers';
import { useCurrency } from '../../context/CurrencyContext';

const AnalyticsOverviewCards = memo(({
  totalIncome,
  totalExpenses,
  averageDailySpending,
  savingsRate,
  budgetAdherence,
  previousPeriodData = {}
}) => {
  const { formatAmount } = useCurrency();
  
  // Calculate trends compared to previous period
  const trends = useMemo(() => {
    const {
      totalIncome: prevIncome = 0,
      totalExpenses: prevExpenses = 0,
      averageDailySpending: prevDaily = 0,
      savingsRate: prevSavings = 0
    } = previousPeriodData;

    return {
      income: getTrendIndicator(((totalIncome - prevIncome) / (prevIncome || 1)) * 100),
      expenses: getTrendIndicator(((totalExpenses - prevExpenses) / (prevExpenses || 1)) * 100),
      daily: getTrendIndicator(((averageDailySpending - prevDaily) / (prevDaily || 1)) * 100),
      savings: getTrendIndicator(savingsRate - prevSavings)
    };
  }, [totalIncome, totalExpenses, averageDailySpending, savingsRate, previousPeriodData]);

  // Card configuration
  const cards = useMemo(() => [
    {
      id: 'income-vs-expenses',
      title: 'Income vs Expenses',
      value: formatAmount(totalIncome - totalExpenses, { showSymbol: true }),
      subtitle: `${formatAmount(totalIncome, { showSymbol: true })} income, ${formatAmount(totalExpenses, { showSymbol: true })} expenses`,
      icon: CurrencyDollarIcon,
      color: totalIncome >= totalExpenses ? 'green' : 'red',
      trend: trends.income,
      description: 'Net income after expenses'
    },
    {
      id: 'daily-spending',
      title: 'Avg Daily Spending',
      value: formatAmount(averageDailySpending, { showSymbol: true }),
      subtitle: 'Based on selected period',
      icon: ArrowTrendingUpIcon,
      color: 'blue',
      trend: trends.daily,
      description: 'Average amount spent per day'
    },
    {
      id: 'savings-rate',
      title: 'Savings Rate',
      value: `${savingsRate}%`,
      subtitle: 'Of total income saved',
      icon: BanknotesIcon,
      color: savingsRate >= 20 ? 'green' : savingsRate >= 10 ? 'yellow' : 'red',
      trend: trends.savings,
      description: 'Percentage of income saved'
    },
    {
      id: 'budget-adherence',
      title: 'Budget Adherence',
      value: `${budgetAdherence}%`,
      subtitle: 'Overall budget performance',
      icon: ChartBarIcon,
      color: budgetAdherence >= 80 ? 'green' : budgetAdherence >= 60 ? 'yellow' : 'red',
      trend: { icon: '→', color: 'text-gray-600 dark:text-gray-400', trend: 'stable' },
      description: 'How well you stick to budgets'
    }
  ], [totalIncome, totalExpenses, averageDailySpending, savingsRate, budgetAdherence, trends]);

  // Color classes for different states
  const colorClasses = {
    green: {
      icon: 'text-green-600 dark:text-green-400',
      bg: 'bg-green-100 dark:bg-green-900/20',
      value: 'text-green-700 dark:text-green-300'
    },
    red: {
      icon: 'text-red-600 dark:text-red-400',
      bg: 'bg-red-100 dark:bg-red-900/20',
      value: 'text-red-700 dark:text-red-300'
    },
    blue: {
      icon: 'text-blue-600 dark:text-blue-400',
      bg: 'bg-blue-100 dark:bg-blue-900/20',
      value: 'text-blue-700 dark:text-blue-300'
    },
    yellow: {
      icon: 'text-yellow-600 dark:text-yellow-400',
      bg: 'bg-yellow-100 dark:bg-yellow-900/20',
      value: 'text-yellow-700 dark:text-yellow-300'
    }
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {cards.map((card) => {
        const Icon = card.icon;
        const colors = colorClasses[card.color];
        
        return (
          <div
            key={card.id}
            className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow border border-gray-200 dark:border-gray-700 transition-base interactive-card hover-glow"
            role="article"
            aria-label={`${card.title}: ${card.value}`}
          >
            {/* Header with Icon and Title */}
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center space-x-3">
                <div className={`p-3 rounded-lg ${colors.bg} transition-all duration-200`}>
                  <Icon className={`h-6 w-6 ${colors.icon}`} />
                </div>
                <div>
                  <h3 className="text-sm font-medium text-gray-600 dark:text-gray-300">
                    {card.title}
                  </h3>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    {card.description}
                  </p>
                </div>
              </div>
            </div>

            {/* Value */}
            <div className="mb-3">
              <p className={`text-2xl font-bold ${colors.value} transition-all duration-200`}>
                {card.value}
              </p>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                {card.subtitle}
              </p>
            </div>

            {/* Trend Indicator */}
            <div className="flex items-center space-x-2">
              <span 
                className={`text-sm font-medium ${card.trend.color} transition-all duration-200`}
                aria-label={`Trend: ${card.trend.trend}`}
              >
                {card.trend.icon}
              </span>
              <span className="text-xs text-gray-500 dark:text-gray-400">
                vs previous period
              </span>
            </div>

            {/* Hover Enhancement */}
            <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-blue-500/0 to-blue-500/0 hover:from-blue-500/5 hover:to-blue-500/10 transition-all duration-200 pointer-events-none" />
          </div>
        );
      })}
    </div>
  );
});

AnalyticsOverviewCards.displayName = 'AnalyticsOverviewCards';

export default AnalyticsOverviewCards;
