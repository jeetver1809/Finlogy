import React, { memo } from 'react';
import { ArrowTopRightOnSquareIcon, ArrowTrendingUpIcon, ArrowTrendingDownIcon } from '@heroicons/react/24/outline';
import { formatCurrency, getTrendIndicator } from '../../utils/analyticsHelpers';
import { createAnalyticsUrl } from '../../utils/analyticsIntegration';

// Mini Analytics Widget for Dashboard
const AnalyticsWidget = memo(({ 
  title, 
  value, 
  subtitle, 
  trend, 
  icon: Icon, 
  color = 'blue',
  analyticsFilter = {},
  onNavigateToAnalytics,
  showTrend = true,
  compact = false 
}) => {
  
  const colorClasses = {
    blue: {
      bg: 'bg-blue-50 dark:bg-blue-900/20',
      icon: 'text-blue-600 dark:text-blue-400',
      value: 'text-blue-700 dark:text-blue-300',
      border: 'border-blue-200 dark:border-blue-800'
    },
    green: {
      bg: 'bg-green-50 dark:bg-green-900/20',
      icon: 'text-green-600 dark:text-green-400',
      value: 'text-green-700 dark:text-green-300',
      border: 'border-green-200 dark:border-green-800'
    },
    red: {
      bg: 'bg-red-50 dark:bg-red-900/20',
      icon: 'text-red-600 dark:text-red-400',
      value: 'text-red-700 dark:text-red-300',
      border: 'border-red-200 dark:border-red-800'
    },
    yellow: {
      bg: 'bg-yellow-50 dark:bg-yellow-900/20',
      icon: 'text-yellow-600 dark:text-yellow-400',
      value: 'text-yellow-700 dark:text-yellow-300',
      border: 'border-yellow-200 dark:border-yellow-800'
    }
  };

  const colors = colorClasses[color];
  
  const handleViewAnalytics = () => {
    if (onNavigateToAnalytics) {
      const url = createAnalyticsUrl(analyticsFilter);
      onNavigateToAnalytics(url);
    }
  };

  const getTrendIcon = (trendValue) => {
    if (trendValue > 0) return ArrowTrendingUpIcon;
    if (trendValue < 0) return ArrowTrendingDownIcon;
    return null;
  };

  const TrendIcon = showTrend && trend ? getTrendIcon(trend.percentage) : null;

  return (
    <div className={`
      bg-white dark:bg-gray-800 rounded-lg border ${colors.border} 
      transition-base interactive-card hover-glow
      ${compact ? 'p-4' : 'p-6'}
    `}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center space-x-3">
          {Icon && (
            <div className={`p-2 rounded-lg ${colors.bg}`}>
              <Icon className={`h-5 w-5 ${colors.icon}`} />
            </div>
          )}
          <div>
            <h3 className={`font-medium text-gray-900 dark:text-white ${compact ? 'text-sm' : 'text-base'}`}>
              {title}
            </h3>
            {subtitle && (
              <p className="text-xs text-gray-500 dark:text-gray-400">
                {subtitle}
              </p>
            )}
          </div>
        </div>
        
        {/* View Analytics Button */}
        <button
          onClick={handleViewAnalytics}
          className="p-2 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 transition-all duration-200"
          title="View in Analytics"
        >
          <ArrowTopRightOnSquareIcon className="h-4 w-4" />
        </button>
      </div>

      {/* Value */}
      <div className="mb-3">
        <p className={`font-bold ${colors.value} ${compact ? 'text-xl' : 'text-2xl'}`}>
          {value}
        </p>
      </div>

      {/* Trend Indicator */}
      {showTrend && trend && (
        <div className="flex items-center space-x-2">
          {TrendIcon && (
            <TrendIcon className={`h-4 w-4 ${
              trend.percentage > 0 ? 'text-green-500' : 'text-red-500'
            }`} />
          )}
          <span className={`text-sm font-medium ${
            trend.percentage > 0 ? 'text-green-600 dark:text-green-400' : 
            trend.percentage < 0 ? 'text-red-600 dark:text-red-400' : 
            'text-gray-600 dark:text-gray-400'
          }`}>
            {trend.percentage > 0 ? '+' : ''}{trend.percentage.toFixed(1)}%
          </span>
          <span className="text-xs text-gray-500 dark:text-gray-400">
            vs last month
          </span>
        </div>
      )}
    </div>
  );
});

// Mini Chart Widget for Dashboard
const MiniChartWidget = memo(({ 
  title, 
  data, 
  chartType = 'line',
  height = 60,
  analyticsFilter = {},
  onNavigateToAnalytics 
}) => {
  
  const handleViewAnalytics = () => {
    if (onNavigateToAnalytics) {
      const url = createAnalyticsUrl(analyticsFilter);
      onNavigateToAnalytics(url);
    }
  };

  // Simple SVG mini chart
  const renderMiniChart = () => {
    if (!data || data.length === 0) return null;
    
    const maxValue = Math.max(...data.map(d => d.value));
    const minValue = Math.min(...data.map(d => d.value));
    const range = maxValue - minValue || 1;
    
    const points = data.map((d, i) => {
      const x = (i / (data.length - 1)) * 100;
      const y = 100 - ((d.value - minValue) / range) * 100;
      return `${x},${y}`;
    }).join(' ');

    return (
      <svg 
        width="100%" 
        height={height} 
        viewBox="0 0 100 100" 
        preserveAspectRatio="none"
        className="text-blue-500"
      >
        <polyline
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          points={points}
          className="drop-shadow-sm"
        />
        <defs>
          <linearGradient id="miniGradient" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0.3"/>
            <stop offset="100%" stopColor="currentColor" stopOpacity="0.1"/>
          </linearGradient>
        </defs>
        <polygon
          fill="url(#miniGradient)"
          points={`0,100 ${points} 100,100`}
        />
      </svg>
    );
  };

  return (
    <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700 transition-base interactive-card hover-glow">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-medium text-gray-900 dark:text-white">
          {title}
        </h3>
        <button
          onClick={handleViewAnalytics}
          className="p-1 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 rounded transition-colors"
          title="View in Analytics"
        >
          <ArrowTopRightOnSquareIcon className="h-4 w-4" />
        </button>
      </div>

      {/* Mini Chart */}
      <div className="relative">
        {renderMiniChart()}
      </div>

      {/* Summary */}
      {data && data.length > 0 && (
        <div className="mt-2 flex justify-between text-xs text-gray-500 dark:text-gray-400">
          <span>
            {data.length} data points
          </span>
          <span>
            Latest: {formatCurrency(data[data.length - 1]?.value || 0)}
          </span>
        </div>
      )}
    </div>
  );
});

// Category Insight Widget
const CategoryInsightWidget = memo(({ 
  category, 
  amount, 
  percentage, 
  trend,
  budgetStatus,
  onNavigateToAnalytics 
}) => {
  
  const handleViewCategory = () => {
    if (onNavigateToAnalytics) {
      const url = createAnalyticsUrl({ category: category.toLowerCase() });
      onNavigateToAnalytics(url);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'exceeded': return 'text-red-600 dark:text-red-400';
      case 'warning': return 'text-yellow-600 dark:text-yellow-400';
      default: return 'text-green-600 dark:text-green-400';
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700 transition-base interactive-card hover-glow">
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-sm font-medium text-gray-900 dark:text-white">
              {category}
            </h4>
            <button
              onClick={handleViewCategory}
              className="p-1 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 rounded transition-colors"
              title="View category analytics"
            >
              <ArrowTopRightOnSquareIcon className="h-3 w-3" />
            </button>
          </div>
          
          <div className="flex items-center justify-between mb-2">
            <span className="text-lg font-bold text-gray-900 dark:text-white">
              {formatCurrency(amount)}
            </span>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {percentage}%
            </span>
          </div>
          
          {/* Progress Bar */}
          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mb-2">
            <div
              className="bg-blue-500 h-2 rounded-full transition-all duration-300"
              style={{ width: `${Math.min(percentage, 100)}%` }}
            />
          </div>
          
          {/* Status and Trend */}
          <div className="flex items-center justify-between text-xs">
            {budgetStatus && (
              <span className={`font-medium ${getStatusColor(budgetStatus.status)}`}>
                {budgetStatus.status === 'exceeded' ? 'Over Budget' :
                 budgetStatus.status === 'warning' ? 'Near Limit' : 'On Track'}
              </span>
            )}
            {trend && (
              <span className={`${trend > 0 ? 'text-red-500' : 'text-green-500'}`}>
                {trend > 0 ? '+' : ''}{trend.toFixed(1)}%
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
});

AnalyticsWidget.displayName = 'AnalyticsWidget';
MiniChartWidget.displayName = 'MiniChartWidget';
CategoryInsightWidget.displayName = 'CategoryInsightWidget';

export default AnalyticsWidget;
export { MiniChartWidget, CategoryInsightWidget };
