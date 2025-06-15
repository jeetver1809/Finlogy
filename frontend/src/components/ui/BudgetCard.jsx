import React, { useState, useEffect, memo, useCallback, useMemo } from 'react';
import { PencilIcon, TrashIcon, CheckCircleIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline';
import { useTheme } from '../../context/ThemeContext';
import CategoryIcon from './CategoryIcon';
import { getCategoryColors } from '../../utils/categoryConfig';

const BudgetCard = memo(({
  budget,
  onEdit,
  onDelete,
  CurrencyDisplay,
  getBudgetStatus,
  getProgressBarColor
}) => {
  const { isDark } = useTheme();
  const [isHovered, setIsHovered] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [showCelebration, setShowCelebration] = useState(false);

  // Memoized calculations to prevent recalculation on every render
  const budgetData = useMemo(() => {
    const { status } = getBudgetStatus(budget);
    const percentage = Math.min((budget.spent / budget.amount) * 100, 100);
    return {
      status,
      percentage,
      isOnTrack: status === 'on-track',
      isNearLimit: status === 'warning',
      isExceeded: status === 'exceeded'
    };
  }, [budget, getBudgetStatus]);

  // Memoized event handlers
  const handleMouseEnter = useCallback(() => setIsHovered(true), []);
  const handleMouseLeave = useCallback(() => setIsHovered(false), []);
  const handleToggleExpanded = useCallback(() => setIsExpanded(prev => !prev), []);
  const handleEdit = useCallback((e) => {
    e.stopPropagation();
    onEdit(budget);
  }, [budget, onEdit]);
  const handleDelete = useCallback((e) => {
    e.stopPropagation();
    onDelete(budget._id);
  }, [budget._id, onDelete]);

  // Trigger celebration animation only when budget goal is achieved within limits
  useEffect(() => {
    if (budgetData.percentage >= 100 && budgetData.isOnTrack && !showCelebration) {
      setShowCelebration(true);
      setTimeout(() => setShowCelebration(false), 2000);
    }
  }, [budgetData.percentage, budgetData.isOnTrack, showCelebration]);

  const getStatusIcon = () => {
    if (budgetData.isExceeded) {
      return <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />;
    }
    if (budgetData.isOnTrack && budgetData.percentage > 50) {
      return <CheckCircleIcon className="h-5 w-5 text-green-500" />;
    }
    return null;
  };

  const getStatusMessage = () => {
    if (budgetData.isExceeded) return "Budget exceeded! Consider reviewing your spending.";
    if (budgetData.isNearLimit) return "You're approaching your budget limit.";
    if (budgetData.percentage > 75) return "Great progress! You're on track.";
    return "Keep up the good work!";
  };

  return (
    <div 
      className={`
        bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 
        p-6 transition-all duration-300 ease-in-out cursor-pointer
        interactive-card hover-brighten
        ${isHovered ? 'ring-2 ring-purple-500/20 dark:ring-purple-400/20 shadow-lg' : ''}
        ${showCelebration ? 'budget-celebration' : ''}
        ${isExpanded ? 'expandable-card expanded' : 'expandable-card'}
      `}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      onClick={handleToggleExpanded}
    >
      {/* Header */}
      <div className="flex justify-between items-start mb-4">
        <div className={`transition-all duration-200 ${isHovered ? 'translate-x-1' : ''}`}>
          <div className="flex items-center space-x-3 mb-2">
            <CategoryIcon
              category={budget.category}
              size="md"
              variant="soft"
              isDark={isDark}
            />
            <div className="flex items-center space-x-2">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                {budget.name}
              </h3>
              {getStatusIcon()}
            </div>
          </div>
          <div className="ml-12">
            <span className={`
              inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
              transition-all duration-200
              ${isHovered ? 'scale-105' : 'scale-100'}
            `}
            style={{
              backgroundColor: getCategoryColors(budget.category, isDark).secondary,
              color: getCategoryColors(budget.category, isDark).text,
              border: `1px solid ${getCategoryColors(budget.category, isDark).border}`
            }}
            >
              {budget.category === 'total' ? 'Total Budget' : budget.category.charAt(0).toUpperCase() + budget.category.slice(1)}
            </span>
          </div>
        </div>
        <div className={`
          flex space-x-2 transition-all duration-200
          ${isHovered ? 'scale-110' : 'scale-100'}
        `}>
          <button
            onClick={handleEdit}
            className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 transition-all duration-200"
          >
            <PencilIcon className="h-4 w-4" />
          </button>
          <button
            onClick={handleDelete}
            className="p-2 text-gray-400 hover:text-red-600 dark:hover:text-red-400 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 transition-all duration-200"
          >
            <TrashIcon className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Progress Section */}
      <div className="mb-4">
        <div className="flex justify-between text-sm text-gray-600 dark:text-gray-400 mb-2">
          <span className="tooltip tooltip-container">
            Spent: <CurrencyDisplay amount={budget.spent} size="sm" className="text-gray-600 dark:text-gray-400" />
            <div className="tooltip-content tooltip-left">
              Amount spent from this budget
            </div>
          </span>
          <span className="tooltip tooltip-container">
            Budget: <CurrencyDisplay amount={budget.amount} size="sm" className="text-gray-600 dark:text-gray-400" />
            <div className="tooltip-content tooltip-right">
              Total budget amount allocated
            </div>
          </span>
        </div>
        
        {/* Animated Progress Bar */}
        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3 overflow-hidden">
          <div
            className={`
              h-3 rounded-full animated-progress transition-all duration-500 ease-out
              ${showCelebration ? 'budget-success-pulse' : ''}
              ${isHovered ? 'shadow-lg' : ''}
            `}
            style={{
              width: `${budgetData.percentage}%`,
              '--progress-width': `${budgetData.percentage}%`,
              backgroundColor: budgetData.status === 'exceeded'
                ? (isDark ? '#DC2626' : '#EF4444')
                : budgetData.status === 'warning'
                ? (isDark ? '#D97706' : '#F59E0B')
                : getCategoryColors(budget.category, isDark).primary
            }}
          />
        </div>

        <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400 mt-2">
          <span className={`transition-all duration-200 ${isHovered ? 'font-medium' : ''}`}>
            {budgetData.percentage.toFixed(1)}% used
          </span>
          <span className={`transition-all duration-200 ${isHovered ? 'font-medium' : ''}`}>
            <CurrencyDisplay 
              amount={budget.amount - budget.spent} 
              size="xs" 
              className="text-gray-500 dark:text-gray-400" 
            /> remaining
          </span>
        </div>
      </div>

      {/* Status and Period Info */}
      <div className="flex justify-between items-center text-xs text-gray-500 dark:text-gray-400">
        <span className={`transition-all duration-200 ${isHovered ? 'scale-105' : ''}`}>
          {budget.period.charAt(0).toUpperCase() + budget.period.slice(1)} budget
        </span>
        <span className={`
          px-2 py-1 rounded-full transition-all duration-200
          ${budgetData.status === 'exceeded' ? 'bg-red-100 dark:bg-red-900/50 text-red-800 dark:text-red-300' :
            budgetData.status === 'warning' ? 'bg-yellow-100 dark:bg-yellow-900/50 text-yellow-800 dark:text-yellow-300' :
            'bg-green-100 dark:bg-green-900/50 text-green-800 dark:text-green-300'
          }
          ${isHovered ? 'scale-105 shadow-md' : ''}
        `}>
          {budgetData.status === 'exceeded' ? 'Over Budget' :
           budgetData.status === 'warning' ? 'Near Limit' : 'On Track'}
        </span>
      </div>

      {/* Expanded Content */}
      {isExpanded && (
        <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700 space-y-3 animate-slide-in-up">
          {/* Status Message */}
          <div className={`
            p-3 rounded-lg text-sm
            ${budgetData.isExceeded ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300' :
              budgetData.isNearLimit ? 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-300' :
              'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300'
            }
          `}>
            {getStatusMessage()}
          </div>

          {/* Budget Details */}
          {budget.description && (
            <div>
              <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-1">Description</h4>
              <p className="text-sm text-gray-600 dark:text-gray-400">{budget.description}</p>
            </div>
          )}

          {/* Alert Threshold */}
          <div className="flex justify-between items-center">
            <span className="text-sm text-gray-600 dark:text-gray-400">Alert Threshold</span>
            <span className="text-sm font-medium text-gray-900 dark:text-white">{budget.alertThreshold}%</span>
          </div>

          {/* Budget Period Dates */}
          <div className="flex justify-between items-center">
            <span className="text-sm text-gray-600 dark:text-gray-400">Period</span>
            <span className="text-sm font-medium text-gray-900 dark:text-white">
              {new Date(budget.startDate).toLocaleDateString()} - {new Date(budget.endDate).toLocaleDateString()}
            </span>
          </div>
        </div>
      )}
    </div>
  );
});

export default BudgetCard;
