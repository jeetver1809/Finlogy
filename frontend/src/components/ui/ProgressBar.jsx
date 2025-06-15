import React, { useState, useEffect } from 'react';

const ProgressBar = ({ 
  value, 
  max = 100, 
  className = '', 
  color = 'blue',
  showLabel = true,
  animated = true,
  size = 'md',
  tooltip,
  onHover,
  celebrateOnComplete = false
}) => {
  const [isHovered, setIsHovered] = useState(false);
  const [animatedValue, setAnimatedValue] = useState(0);
  const [showCelebration, setShowCelebration] = useState(false);

  const percentage = Math.min((value / max) * 100, 100);

  // Animate progress bar fill
  useEffect(() => {
    if (animated) {
      const timer = setTimeout(() => {
        setAnimatedValue(percentage);
      }, 100);
      return () => clearTimeout(timer);
    } else {
      setAnimatedValue(percentage);
    }
  }, [percentage, animated]);

  // Celebration effect only when reaching 100% within budget (not exceeded)
  useEffect(() => {
    if (celebrateOnComplete && percentage >= 100 && color === 'green' && !showCelebration) {
      setShowCelebration(true);
      setTimeout(() => setShowCelebration(false), 2000);
    }
  }, [percentage, celebrateOnComplete, showCelebration, color]);

  const colorClasses = {
    blue: 'bg-blue-500',
    green: 'bg-green-500',
    yellow: 'bg-yellow-500',
    red: 'bg-red-500',
    purple: 'bg-purple-500',
    indigo: 'bg-indigo-500',
  };

  const sizeClasses = {
    sm: 'h-1',
    md: 'h-2',
    lg: 'h-3',
    xl: 'h-4',
  };

  const getStatusColor = () => {
    // For budget progress bars, use the passed color which reflects the actual status
    return color;
  };

  const handleMouseEnter = () => {
    setIsHovered(true);
    if (onHover) onHover(true);
  };

  const handleMouseLeave = () => {
    setIsHovered(false);
    if (onHover) onHover(false);
  };

  return (
    <div className={`w-full ${className}`}>
      {/* Label */}
      {showLabel && (
        <div className="flex justify-between text-sm text-gray-600 dark:text-gray-400 mb-1">
          <span className={`transition-all duration-200 ${isHovered ? 'font-medium' : ''}`}>
            Progress
          </span>
          <span className={`transition-all duration-200 ${isHovered ? 'font-medium scale-105' : ''}`}>
            {percentage.toFixed(1)}%
          </span>
        </div>
      )}

      {/* Progress Bar Container */}
      <div 
        className={`
          relative w-full bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden
          ${sizeClasses[size]}
          ${isHovered ? 'shadow-md' : ''}
          ${showCelebration ? 'budget-celebration' : ''}
          transition-all duration-200 ease-in-out
          ${tooltip ? 'tooltip' : ''}
        `}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
      >
        {/* Progress Fill */}
        <div
          className={`
            ${sizeClasses[size]} rounded-full transition-all duration-500 ease-out
            ${colorClasses[getStatusColor()]}
            ${animated ? 'animated-progress' : ''}
            ${isHovered ? 'shadow-lg brightness-110' : ''}
            ${showCelebration ? 'budget-success-pulse' : ''}
            relative overflow-hidden
          `}
          style={{ 
            width: `${animatedValue}%`,
            '--progress-width': `${animatedValue}%`
          }}
        >
          {/* Shimmer effect for active progress */}
          {isHovered && (
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-shimmer" />
          )}
        </div>

        {/* Tooltip */}
        {tooltip && (
          <div className="tooltip-content">
            {tooltip}
          </div>
        )}
      </div>

      {/* Additional Info */}
      {isHovered && (
        <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400 mt-1 animate-slide-in-up">
          <span>{value.toFixed(2)} / {max.toFixed(2)}</span>
          <span>{(max - value).toFixed(2)} remaining</span>
        </div>
      )}

      {/* Celebration Message - Only for successful budget completion */}
      {showCelebration && percentage >= 100 && color === 'green' && (
        <div className="text-center mt-2 animate-slide-in-up">
          <span className="text-sm font-medium text-green-600 dark:text-green-400">
            🎉 Budget goal achieved! Great job staying within limits!
          </span>
        </div>
      )}

      {/* Warning Message for Exceeded Budget */}
      {percentage >= 100 && color === 'red' && (
        <div className="text-center mt-2 animate-slide-in-up">
          <span className="text-sm font-medium text-red-600 dark:text-red-400">
            ⚠️ Budget Exceeded - Consider Reviewing Spending
          </span>
        </div>
      )}
    </div>
  );
};

export default ProgressBar;
