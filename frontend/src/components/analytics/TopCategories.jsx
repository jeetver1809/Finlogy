import React, { memo, useMemo } from 'react';
import { formatCurrency, getCategoryColor } from '../../utils/analyticsHelpers';

const TopCategories = memo(({ categories, totalAmount, maxItems = 5 }) => {
  // Process and limit categories
  const processedCategories = useMemo(() => {
    if (!categories || categories.length === 0) return [];
    
    return categories
      .slice(0, maxItems)
      .map((category, index) => ({
        ...category,
        percentage: totalAmount > 0 ? Math.round((category.amount / totalAmount) * 100) : 0,
        color: getCategoryColor(index)
      }));
  }, [categories, totalAmount, maxItems]);

  // Category icons mapping
  const categoryIcons = {
    'Food & Dining': '🍽️',
    'Transportation': '🚗',
    'Shopping': '🛍️',
    'Entertainment': '🎬',
    'Bills & Utilities': '💡',
    'Healthcare': '🏥',
    'Education': '📚',
    'Travel': '✈️',
    'Groceries': '🛒',
    'Rent': '🏠',
    'Other': '📊'
  };

  // Get icon for category
  const getCategoryIcon = (categoryName) => {
    return categoryIcons[categoryName] || categoryIcons['Other'];
  };

  // Empty state
  if (processedCategories.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow border border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Top Spending Categories
        </h3>
        <div className="text-center py-8">
          <div className="w-16 h-16 mx-auto mb-4 bg-gray-100 dark:bg-gray-700 rounded-full flex items-center justify-center">
            <svg className="w-8 h-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <p className="text-gray-500 dark:text-gray-400">No spending data available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow border border-gray-200 dark:border-gray-700 transition-base interactive-card">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Top Spending Categories
        </h3>
        <span className="text-sm text-gray-500 dark:text-gray-400">
          Last {maxItems} categories
        </span>
      </div>

      {/* Categories List */}
      <div className="space-y-4">
        {processedCategories.map((category, index) => (
          <div
            key={category.category}
            className="group hover:bg-gray-50 dark:hover:bg-gray-700/50 p-3 rounded-lg transition-all duration-200 cursor-pointer"
          >
            <div className="flex items-center justify-between">
              {/* Category Info */}
              <div className="flex items-center space-x-3 flex-1">
                {/* Category Icon */}
                <div 
                  className="w-10 h-10 rounded-lg flex items-center justify-center text-white font-semibold text-sm transition-all duration-200 group-hover:scale-110"
                  style={{ backgroundColor: category.color }}
                >
                  <span className="text-lg">
                    {getCategoryIcon(category.category)}
                  </span>
                </div>
                
                {/* Category Details */}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                    {category.category}
                  </p>
                  <div className="flex items-center space-x-2 mt-1">
                    <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                      <div
                        className="h-2 rounded-full transition-all duration-300 ease-out"
                        style={{ 
                          width: `${category.percentage}%`,
                          backgroundColor: category.color
                        }}
                      />
                    </div>
                    <span className="text-xs text-gray-500 dark:text-gray-400 min-w-0">
                      {category.percentage}%
                    </span>
                  </div>
                </div>
              </div>

              {/* Amount */}
              <div className="text-right ml-4">
                <p className="text-sm font-semibold text-gray-900 dark:text-white">
                  {formatCurrency(category.amount)}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  #{index + 1}
                </p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Summary */}
      {categories && categories.length > maxItems && (
        <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
          <p className="text-sm text-gray-500 dark:text-gray-400 text-center">
            +{categories.length - maxItems} more categories
          </p>
        </div>
      )}

      {/* Total */}
      <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
        <div className="flex justify-between items-center">
          <span className="text-sm font-medium text-gray-600 dark:text-gray-300">
            Total Spending:
          </span>
          <span className="text-lg font-bold text-gray-900 dark:text-white">
            {formatCurrency(totalAmount)}
          </span>
        </div>
      </div>
    </div>
  );
});

TopCategories.displayName = 'TopCategories';

export default TopCategories;
