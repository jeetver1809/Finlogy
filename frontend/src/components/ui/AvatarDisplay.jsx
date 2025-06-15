import React, { useState } from 'react';
import { UserCircleIcon } from '@heroicons/react/24/outline';

const AvatarDisplay = ({
  avatar,
  name,
  size = 'md',
  className = '',
  showFallback = true
}) => {
  const [imageError, setImageError] = useState(false);

  // Size configurations with enhanced circular styling
  const sizeClasses = {
    sm: 'w-8 h-8 rounded-full',
    md: 'w-12 h-12 rounded-full',
    lg: 'w-16 h-16 rounded-full',
    xl: 'w-24 h-24 rounded-full',
    '2xl': 'w-32 h-32 rounded-full'
  };

  // Enhanced shadow and border classes for different sizes
  const enhancedStyling = {
    sm: 'shadow-sm ring-2 ring-white dark:ring-gray-800',
    md: 'shadow-md ring-2 ring-white dark:ring-gray-800',
    lg: 'shadow-lg ring-3 ring-white dark:ring-gray-800',
    xl: 'shadow-xl ring-4 ring-white dark:ring-gray-800',
    '2xl': 'shadow-2xl ring-4 ring-white dark:ring-gray-800'
  };

  const iconSizeClasses = {
    sm: 'w-8 h-8 rounded-full',
    md: 'w-12 h-12 rounded-full',
    lg: 'w-16 h-16 rounded-full',
    xl: 'w-24 h-24 rounded-full',
    '2xl': 'w-32 h-32 rounded-full'
  };

  const textSizeClasses = {
    sm: 'text-xs',
    md: 'text-sm',
    lg: 'text-lg',
    xl: 'text-2xl',
    '2xl': 'text-4xl'
  };

  const handleImageError = () => {
    setImageError(true);
  };

  // If we have an avatar and no image error, show the avatar
  if (avatar && !imageError) {
    return (
      <div className={`${sizeClasses[size]} overflow-hidden flex-shrink-0 ${enhancedStyling[size]} transition-all duration-300 hover:scale-105 hover:shadow-xl ${className}`}>
        <img
          src={`/images/${avatar}`}
          alt={`${name}'s avatar`}
          className="w-full h-full object-cover transition-transform duration-300"
          onError={handleImageError}
        />
      </div>
    );
  }

  // Fallback to initials or icon
  if (showFallback) {
    if (name) {
      // Show initials
      const initials = name
        .split(' ')
        .map(word => word.charAt(0))
        .join('')
        .toUpperCase()
        .slice(0, 2);

      return (
        <div className={`${sizeClasses[size]} bg-gradient-to-br from-blue-500 via-blue-600 to-blue-700 flex items-center justify-center text-white font-bold ${textSizeClasses[size]} ${enhancedStyling[size]} flex-shrink-0 transition-all duration-300 hover:scale-105 hover:shadow-xl hover:from-blue-600 hover:to-blue-800 ${className}`}>
          {initials}
        </div>
      );
    } else {
      // Show icon
      return (
        <div className={`${iconSizeClasses[size]} flex items-center justify-center flex-shrink-0 ${enhancedStyling[size]} transition-all duration-300 hover:scale-105 hover:shadow-xl ${className}`}>
          <UserCircleIcon className={`w-full h-full text-gray-500 dark:text-gray-400 transition-colors duration-300 hover:text-gray-600 dark:hover:text-gray-300`} />
        </div>
      );
    }
  }

  return null;
};

export default AvatarDisplay;
