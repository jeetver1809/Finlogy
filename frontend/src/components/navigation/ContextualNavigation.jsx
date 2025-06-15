import React, { memo } from 'react';
import { 
  ChevronRightIcon, 
  HomeIcon, 
  ChartBarIcon,
  ArrowTopRightOnSquareIcon 
} from '@heroicons/react/24/outline';
import { createAnalyticsUrl } from '../../utils/analyticsIntegration';

// Breadcrumb Navigation Component
const BreadcrumbNavigation = memo(({ 
  items = [], 
  onNavigate,
  showAnalyticsLink = false,
  analyticsFilter = {} 
}) => {
  
  const handleAnalyticsClick = () => {
    if (onNavigate) {
      const url = createAnalyticsUrl(analyticsFilter);
      onNavigate(url);
    }
  };

  return (
    <nav className="flex items-center space-x-2 text-sm text-gray-500 dark:text-gray-400 mb-6">
      {/* Home Icon */}
      <HomeIcon className="h-4 w-4" />
      
      {/* Breadcrumb Items */}
      {items.map((item, index) => (
        <React.Fragment key={index}>
          <ChevronRightIcon className="h-4 w-4" />
          {item.href ? (
            <button
              onClick={() => onNavigate && onNavigate(item.href)}
              className="hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
            >
              {item.label}
            </button>
          ) : (
            <span className="text-gray-900 dark:text-white font-medium">
              {item.label}
            </span>
          )}
        </React.Fragment>
      ))}
      
      {/* Analytics Link */}
      {showAnalyticsLink && (
        <>
          <span className="text-gray-300 dark:text-gray-600">|</span>
          <button
            onClick={handleAnalyticsClick}
            className="flex items-center space-x-1 text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
            title="View in Analytics"
          >
            <ChartBarIcon className="h-4 w-4" />
            <span>Analytics</span>
            <ArrowTopRightOnSquareIcon className="h-3 w-3" />
          </button>
        </>
      )}
    </nav>
  );
});

// Contextual Action Bar
const ContextualActionBar = memo(({ 
  title, 
  actions = [], 
  analyticsAction,
  onNavigateToAnalytics 
}) => {
  
  const handleAnalyticsClick = () => {
    if (onNavigateToAnalytics && analyticsAction) {
      const url = createAnalyticsUrl(analyticsAction.filter || {});
      onNavigateToAnalytics(url);
    }
  };

  return (
    <div className="flex items-center justify-between bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700 mb-6">
      <div>
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
          {title}
        </h2>
        {analyticsAction && (
          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
            {analyticsAction.description}
          </p>
        )}
      </div>
      
      <div className="flex items-center space-x-3">
        {/* Custom Actions */}
        {actions.map((action, index) => (
          <button
            key={index}
            onClick={action.onClick}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              action.variant === 'primary' 
                ? 'bg-blue-600 hover:bg-blue-700 text-white'
                : 'bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300'
            }`}
          >
            {action.icon && <action.icon className="h-4 w-4 mr-2 inline" />}
            {action.label}
          </button>
        ))}
        
        {/* Analytics Action */}
        {analyticsAction && (
          <button
            onClick={handleAnalyticsClick}
            className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 border border-blue-200 dark:border-blue-800 rounded-lg text-blue-700 dark:text-blue-300 hover:from-blue-100 hover:to-indigo-100 dark:hover:from-blue-900/30 dark:hover:to-indigo-900/30 transition-all duration-200"
          >
            <ChartBarIcon className="h-4 w-4" />
            <span className="text-sm font-medium">{analyticsAction.label}</span>
            <ArrowTopRightOnSquareIcon className="h-3 w-3" />
          </button>
        )}
      </div>
    </div>
  );
});

// Quick Analytics Insights Panel
const QuickInsightsPanel = memo(({ 
  insights = [], 
  onNavigateToAnalytics,
  compact = false 
}) => {
  
  const handleInsightClick = (insight) => {
    if (onNavigateToAnalytics && insight.analyticsFilter) {
      const url = createAnalyticsUrl(insight.analyticsFilter);
      onNavigateToAnalytics(url);
    }
  };

  if (insights.length === 0) return null;

  return (
    <div className={`bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 rounded-lg border border-blue-200 dark:border-blue-800 ${compact ? 'p-3' : 'p-4'} mb-6`}>
      <div className="flex items-center justify-between mb-3">
        <h3 className={`font-medium text-blue-900 dark:text-blue-100 ${compact ? 'text-sm' : 'text-base'}`}>
          💡 Quick Insights
        </h3>
        <button
          onClick={() => onNavigateToAnalytics && onNavigateToAnalytics('/analytics')}
          className="text-xs text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium transition-colors"
        >
          View All →
        </button>
      </div>
      
      <div className={`space-y-2 ${compact ? 'text-sm' : ''}`}>
        {insights.slice(0, compact ? 2 : 3).map((insight, index) => (
          <div
            key={index}
            className="flex items-center justify-between p-2 bg-white/50 dark:bg-gray-800/50 rounded cursor-pointer hover:bg-white/70 dark:hover:bg-gray-800/70 transition-colors"
            onClick={() => handleInsightClick(insight)}
          >
            <div className="flex items-center space-x-2">
              <span className="text-lg">{insight.icon}</span>
              <span className="text-blue-800 dark:text-blue-200">
                {insight.message}
              </span>
            </div>
            {insight.value && (
              <span className="font-semibold text-blue-900 dark:text-blue-100">
                {insight.value}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
});

// Data Relationship Indicator
const DataRelationshipIndicator = memo(({ 
  relationships = [], 
  onNavigateToAnalytics 
}) => {
  
  if (relationships.length === 0) return null;

  return (
    <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700 mb-6">
      <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-3">
        🔗 Related Data
      </h3>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {relationships.map((relationship, index) => (
          <button
            key={index}
            onClick={() => {
              if (onNavigateToAnalytics && relationship.analyticsFilter) {
                const url = createAnalyticsUrl(relationship.analyticsFilter);
                onNavigateToAnalytics(url);
              }
            }}
            className="flex items-center space-x-3 p-3 border border-gray-200 dark:border-gray-700 rounded-lg hover:border-blue-300 dark:hover:border-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20 transition-all duration-200 text-left"
          >
            <div className="flex-shrink-0">
              <relationship.icon className="h-5 w-5 text-gray-600 dark:text-gray-400" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                {relationship.title}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                {relationship.description}
              </p>
            </div>
            <ArrowTopRightOnSquareIcon className="h-4 w-4 text-gray-400" />
          </button>
        ))}
      </div>
    </div>
  );
});

BreadcrumbNavigation.displayName = 'BreadcrumbNavigation';
ContextualActionBar.displayName = 'ContextualActionBar';
QuickInsightsPanel.displayName = 'QuickInsightsPanel';
DataRelationshipIndicator.displayName = 'DataRelationshipIndicator';

export {
  BreadcrumbNavigation,
  ContextualActionBar,
  QuickInsightsPanel,
  DataRelationshipIndicator
};
