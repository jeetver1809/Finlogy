import React, { useState, useCallback } from 'react';
import { StarIcon } from '@heroicons/react/24/outline';
import { StarIcon as StarIconSolid } from '@heroicons/react/24/solid';

const StarRating = ({ 
  rating = 0, 
  onRatingChange, 
  size = 'md', 
  readonly = false,
  showLabel = true,
  className = '' 
}) => {
  const [hoverRating, setHoverRating] = useState(0);
  const [isHovering, setIsHovering] = useState(false);

  const sizes = {
    sm: 'h-5 w-5',
    md: 'h-6 w-6',
    lg: 'h-8 w-8',
    xl: 'h-10 w-10'
  };

  const labels = {
    1: 'Poor',
    2: 'Fair', 
    3: 'Good',
    4: 'Very Good',
    5: 'Excellent'
  };

  const handleStarClick = useCallback((starValue) => {
    if (!readonly && onRatingChange) {
      onRatingChange(starValue);
    }
  }, [readonly, onRatingChange]);

  const handleStarHover = useCallback((starValue) => {
    if (!readonly) {
      setHoverRating(starValue);
      setIsHovering(true);
    }
  }, [readonly]);

  const handleMouseLeave = useCallback(() => {
    if (!readonly) {
      setHoverRating(0);
      setIsHovering(false);
    }
  }, [readonly]);

  const getStarColor = (starIndex) => {
    const currentRating = isHovering ? hoverRating : rating;
    if (starIndex <= currentRating) {
      if (currentRating <= 2) return 'text-red-400';
      if (currentRating <= 3) return 'text-yellow-400';
      return 'text-green-400';
    }
    return 'text-gray-300 dark:text-gray-600';
  };

  const getCurrentLabel = () => {
    const currentRating = isHovering ? hoverRating : rating;
    return labels[currentRating] || '';
  };

  return (
    <div className={`flex flex-col items-center space-y-2 ${className}`}>
      {/* Stars */}
      <div 
        className="flex items-center space-x-1"
        onMouseLeave={handleMouseLeave}
        role={readonly ? 'img' : 'radiogroup'}
        aria-label={readonly ? `Rating: ${rating} out of 5 stars` : 'Rate this experience'}
      >
        {[1, 2, 3, 4, 5].map((starValue) => {
          const StarComponent = starValue <= (isHovering ? hoverRating : rating) ? StarIconSolid : StarIcon;
          
          return (
            <button
              key={starValue}
              type="button"
              className={`
                ${sizes[size]} ${getStarColor(starValue)}
                transition-all duration-200 ease-in-out transform
                ${readonly ? 'cursor-default' : 'cursor-pointer hover:scale-110 focus:scale-110'}
                focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 rounded
                ${!readonly ? 'hover:drop-shadow-lg' : ''}
              `}
              onClick={() => handleStarClick(starValue)}
              onMouseEnter={() => handleStarHover(starValue)}
              disabled={readonly}
              aria-label={`${starValue} star${starValue !== 1 ? 's' : ''}`}
              role={readonly ? 'presentation' : 'radio'}
              aria-checked={readonly ? undefined : starValue === rating}
            >
              <StarComponent className="w-full h-full" />
            </button>
          );
        })}
      </div>

      {/* Rating Label */}
      {showLabel && (
        <div className="text-center min-h-[1.5rem]">
          {(rating > 0 || hoverRating > 0) && (
            <div className="flex flex-col items-center space-y-1">
              <span className={`
                text-sm font-medium transition-all duration-200
                ${isHovering ? 'text-blue-600 dark:text-blue-400' : 'text-gray-700 dark:text-gray-300'}
              `}>
                {getCurrentLabel()}
              </span>
              <span className="text-xs text-gray-500 dark:text-gray-400">
                {isHovering ? hoverRating : rating} out of 5 stars
              </span>
            </div>
          )}
          {!readonly && rating === 0 && hoverRating === 0 && (
            <span className="text-sm text-gray-500 dark:text-gray-400">
              Click to rate
            </span>
          )}
        </div>
      )}
    </div>
  );
};

// Compact version for inline use
export const CompactStarRating = ({ rating, size = 'sm', className = '' }) => {
  return (
    <div className={`flex items-center space-x-1 ${className}`}>
      {[1, 2, 3, 4, 5].map((starValue) => {
        const StarComponent = starValue <= rating ? StarIconSolid : StarIcon;
        const color = rating <= 2 ? 'text-red-400' : rating <= 3 ? 'text-yellow-400' : 'text-green-400';
        
        return (
          <StarComponent
            key={starValue}
            className={`h-4 w-4 ${starValue <= rating ? color : 'text-gray-300 dark:text-gray-600'}`}
          />
        );
      })}
      <span className="ml-2 text-sm text-gray-600 dark:text-gray-400">
        ({rating}/5)
      </span>
    </div>
  );
};

export default StarRating;
