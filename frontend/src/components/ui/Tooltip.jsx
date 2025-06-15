import React, { useState, useRef, useEffect } from 'react';

const Tooltip = ({ 
  children, 
  content, 
  position = 'top', 
  delay = 200,
  className = '',
  disabled = false,
  interactive = false,
  maxWidth = '200px'
}) => {
  const [isVisible, setIsVisible] = useState(false);
  const [actualPosition, setActualPosition] = useState(position);
  const timeoutRef = useRef(null);
  const tooltipRef = useRef(null);
  const triggerRef = useRef(null);

  const showTooltip = () => {
    if (disabled) return;
    
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }
    
    timeoutRef.current = setTimeout(() => {
      setIsVisible(true);
      calculatePosition();
    }, delay);
  };

  const hideTooltip = () => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }
    
    if (!interactive) {
      setIsVisible(false);
    } else {
      // For interactive tooltips, add a small delay before hiding
      timeoutRef.current = setTimeout(() => {
        setIsVisible(false);
      }, 100);
    }
  };

  const calculatePosition = () => {
    if (!tooltipRef.current || !triggerRef.current) return;

    const triggerRect = triggerRef.current.getBoundingClientRect();
    const tooltipRect = tooltipRef.current.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const scrollY = window.scrollY;
    const scrollX = window.scrollX;

    let newPosition = position;

    // Add margins for better spacing
    const margin = 10;

    // Check if tooltip would overflow viewport and adjust position
    switch (position) {
      case 'top':
        if (triggerRect.top - tooltipRect.height - margin < 0) {
          newPosition = 'bottom';
        }
        break;
      case 'bottom':
        if (triggerRect.bottom + tooltipRect.height + margin > viewportHeight) {
          newPosition = 'top';
        }
        break;
      case 'left':
        if (triggerRect.left - tooltipRect.width - margin < scrollX) {
          newPosition = 'right';
        }
        break;
      case 'right':
        if (triggerRect.right + tooltipRect.width + margin > viewportWidth + scrollX) {
          newPosition = 'left';
        }
        break;
    }

    // Additional check for horizontal centering on top/bottom positions
    if ((newPosition === 'top' || newPosition === 'bottom')) {
      const tooltipLeft = triggerRect.left + (triggerRect.width / 2) - (tooltipRect.width / 2);
      if (tooltipLeft < scrollX + margin) {
        // Tooltip would overflow left, keep it within bounds
        newPosition = newPosition; // Keep the same vertical position
      } else if (tooltipLeft + tooltipRect.width > viewportWidth + scrollX - margin) {
        // Tooltip would overflow right, keep it within bounds
        newPosition = newPosition; // Keep the same vertical position
      }
    }

    setActualPosition(newPosition);
  };

  useEffect(() => {
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  const getPositionClasses = () => {
    const baseClasses = 'absolute z-50 px-3 py-2 text-sm font-medium text-white bg-gray-900 rounded-lg shadow-lg dark:bg-gray-700 max-w-xs';

    switch (actualPosition) {
      case 'top':
        return `${baseClasses} bottom-full left-1/2 transform -translate-x-1/2 mb-2`;
      case 'bottom':
        return `${baseClasses} top-full left-1/2 transform -translate-x-1/2 mt-2`;
      case 'left':
        return `${baseClasses} right-full top-1/2 transform -translate-y-1/2 mr-2`;
      case 'right':
        return `${baseClasses} left-full top-1/2 transform -translate-y-1/2 ml-2`;
      default:
        return `${baseClasses} bottom-full left-1/2 transform -translate-x-1/2 mb-2`;
    }
  };

  const getArrowClasses = () => {
    const baseClasses = 'absolute w-2 h-2 bg-gray-900 dark:bg-gray-700 transform rotate-45';
    
    switch (actualPosition) {
      case 'top':
        return `${baseClasses} top-full left-1/2 transform -translate-x-1/2 -translate-y-1/2`;
      case 'bottom':
        return `${baseClasses} bottom-full left-1/2 transform -translate-x-1/2 translate-y-1/2`;
      case 'left':
        return `${baseClasses} left-full top-1/2 transform -translate-x-1/2 -translate-y-1/2`;
      case 'right':
        return `${baseClasses} right-full top-1/2 transform translate-x-1/2 -translate-y-1/2`;
      default:
        return `${baseClasses} top-full left-1/2 transform -translate-x-1/2 -translate-y-1/2`;
    }
  };

  return (
    <div 
      className={`relative inline-block ${className}`}
      ref={triggerRef}
      onMouseEnter={showTooltip}
      onMouseLeave={hideTooltip}
    >
      {children}
      
      {isVisible && content && (
        <div
          ref={tooltipRef}
          className={`
            ${getPositionClasses()}
            transition-all duration-200 ease-in-out
            ${isVisible ? 'opacity-100 visible' : 'opacity-0 invisible'}
          `}
          style={{ maxWidth }}
          onMouseEnter={() => {
            if (interactive && timeoutRef.current) {
              clearTimeout(timeoutRef.current);
            }
          }}
          onMouseLeave={() => {
            if (interactive) {
              hideTooltip();
            }
          }}
        >
          {/* Tooltip Content */}
          <div className="relative z-10">
            {typeof content === 'string' ? (
              <span>{content}</span>
            ) : (
              content
            )}
          </div>
          
          {/* Arrow */}
          <div className={getArrowClasses()} />
        </div>
      )}
    </div>
  );
};

// Higher-order component for easy tooltip wrapping
export const withTooltip = (Component, tooltipProps) => {
  return React.forwardRef((props, ref) => (
    <Tooltip {...tooltipProps}>
      <Component {...props} ref={ref} />
    </Tooltip>
  ));
};

export default Tooltip;
