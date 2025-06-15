import React, { useState, memo, useMemo, useCallback } from 'react';

// Memoized style objects to prevent recreation on every render
const colorClasses = {
  green: 'text-green-600 dark:text-green-400',
  red: 'text-red-600 dark:text-red-400',
  blue: 'text-blue-600 dark:text-blue-400',
  yellow: 'text-yellow-600 dark:text-yellow-400',
};

const changeColorClasses = {
  increase: 'text-green-600 dark:text-green-400',
  decrease: 'text-red-600 dark:text-red-400',
  neutral: 'text-gray-600 dark:text-gray-400',
};

const iconBgClasses = {
  green: 'bg-green-100 dark:bg-green-900/20',
  red: 'bg-red-100 dark:bg-red-900/20',
  blue: 'bg-blue-100 dark:bg-blue-900/20',
  yellow: 'bg-yellow-100 dark:bg-yellow-900/20',
};

const StatCard = memo(({ name, value, icon: Icon, change, changeType, color, tooltip }) => {
  const [isHovered, setIsHovered] = useState(false);

  // Memoized event handlers to prevent recreation
  const handleMouseEnter = useCallback(() => setIsHovered(true), []);
  const handleMouseLeave = useCallback(() => setIsHovered(false), []);

  // Memoized computed classes
  const computedClasses = useMemo(() => ({
    container: `
      bg-white dark:bg-gray-800 p-6 rounded-lg shadow border border-gray-200 dark:border-gray-700
      interactive-card hover-brighten dashboard-card
      ${isHovered ? 'ring-2 ring-blue-500/20 dark:ring-blue-400/20' : ''}
      transition-all duration-200 ease-in-out
    `,
    iconContainer: `
      p-3 rounded-lg transition-all duration-200 ease-in-out
      ${iconBgClasses[color]}
      ${isHovered ? 'scale-110' : 'scale-100'}
    `,
    value: `
      text-2xl font-semibold text-gray-900 dark:text-white
      transition-all duration-200 ease-in-out
      ${isHovered ? 'scale-105' : 'scale-100'}
    `,
    change: `
      ml-2 flex items-baseline text-sm font-semibold
      ${changeColorClasses[changeType]}
      transition-all duration-200 ease-in-out
      ${isHovered ? 'translate-x-1' : 'translate-x-0'}
    `,
    arrow: `
      w-3 h-3 mr-1 transition-transform duration-200
      ${changeType === 'increase' ? 'rotate-0' : 'rotate-180'}
      ${isHovered ? 'scale-110' : 'scale-100'}
    `
  }), [isHovered, color, changeType]);

  return (
    <div
      className={computedClasses.container}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      <div className="flex items-center">
        <div className="flex-shrink-0">
          <div className={computedClasses.iconContainer}>
            <Icon className={`h-6 w-6 ${colorClasses[color]} transition-all duration-200`} />
          </div>
        </div>
        <div className="ml-5 w-0 flex-1">
          <dl>
            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
              {name}
              {tooltip && (
                <div className="tooltip inline-block ml-1">
                  <svg className="w-4 h-4 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 cursor-help" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-8-3a1 1 0 00-.867.5 1 1 0 11-1.731-1A3 3 0 0113 8a3.001 3.001 0 01-2 2.83V11a1 1 0 11-2 0v-1a1 1 0 011-1 1 1 0 100-2zm0 8a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                  </svg>
                  <div className="tooltip-content">
                    {tooltip}
                  </div>
                </div>
              )}
            </dt>
            <dd className="flex items-baseline">
              <div className={computedClasses.value}>
                {value}
              </div>
              {change && (
                <div className={computedClasses.change}>
                  <svg
                    className={computedClasses.arrow}
                    fill="currentColor"
                    viewBox="0 0 20 20"
                  >
                    <path fillRule="evenodd" d="M5.293 7.707a1 1 0 010-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 01-1.414 1.414L11 5.414V17a1 1 0 11-2 0V5.414L6.707 7.707a1 1 0 01-1.414 0z" clipRule="evenodd" />
                  </svg>
                  {change}
                </div>
              )}
            </dd>
          </dl>
        </div>
      </div>
    </div>
  );
});

export default StatCard;
