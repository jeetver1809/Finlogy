/**
 * 🎨 CATEGORY ICON COMPONENT
 * 
 * Displays category icons with consistent styling and colors
 * Supports different sizes and themes
 */

import React from 'react';
import { getCategoryConfig, getCategoryColors } from '../../utils/categoryConfig';

const CategoryIcon = ({ 
  category, 
  size = 'md', 
  variant = 'filled',
  className = '',
  showBackground = true,
  isDark = false,
  onClick = null
}) => {
  const config = getCategoryConfig(category);
  const colors = getCategoryColors(category, isDark);
  const IconComponent = config.icon;

  // Size configurations
  const sizeConfig = {
    xs: {
      icon: 'h-3 w-3',
      container: 'p-1',
      text: 'text-xs'
    },
    sm: {
      icon: 'h-4 w-4',
      container: 'p-1.5',
      text: 'text-sm'
    },
    md: {
      icon: 'h-5 w-5',
      container: 'p-2',
      text: 'text-base'
    },
    lg: {
      icon: 'h-6 w-6',
      container: 'p-2.5',
      text: 'text-lg'
    },
    xl: {
      icon: 'h-8 w-8',
      container: 'p-3',
      text: 'text-xl'
    }
  };

  const currentSize = sizeConfig[size] || sizeConfig.md;

  // Variant styles
  const getVariantStyles = () => {
    switch (variant) {
      case 'filled':
        return {
          backgroundColor: colors.primary,
          color: isDark ? colors.text : '#FFFFFF',
          border: `1px solid ${colors.border}`
        };
      case 'outlined':
        return {
          backgroundColor: 'transparent',
          color: colors.primary,
          border: `2px solid ${colors.primary}`
        };
      case 'soft':
        return {
          backgroundColor: colors.secondary,
          color: colors.text,
          border: `1px solid ${colors.border}`
        };
      case 'minimal':
        return {
          backgroundColor: 'transparent',
          color: colors.primary,
          border: 'none'
        };
      default:
        return {
          backgroundColor: colors.primary,
          color: '#FFFFFF',
          border: `1px solid ${colors.border}`
        };
    }
  };

  const variantStyles = getVariantStyles();

  const containerClasses = `
    inline-flex items-center justify-center rounded-lg transition-all duration-200
    ${currentSize.container}
    ${onClick ? 'cursor-pointer hover:scale-105 hover:shadow-md' : ''}
    ${className}
  `.trim();

  const iconClasses = `
    ${currentSize.icon}
    transition-all duration-200
  `.trim();

  if (!showBackground) {
    return (
      <IconComponent 
        className={`${iconClasses} ${className}`}
        style={{ color: colors.primary }}
        onClick={onClick}
      />
    );
  }

  return (
    <div
      className={containerClasses}
      style={variantStyles}
      onClick={onClick}
      title={config.description}
    >
      <IconComponent className={iconClasses} />
    </div>
  );
};

// Category Icon with Label
export const CategoryIconWithLabel = ({ 
  category, 
  size = 'md',
  variant = 'filled',
  showLabel = true,
  labelPosition = 'bottom',
  className = '',
  isDark = false,
  onClick = null
}) => {
  const config = getCategoryConfig(category);
  const colors = getCategoryColors(category, isDark);
  const sizeConfig = {
    xs: 'text-xs',
    sm: 'text-sm', 
    md: 'text-sm',
    lg: 'text-base',
    xl: 'text-lg'
  };

  const labelClasses = `
    ${sizeConfig[size] || sizeConfig.md}
    font-medium truncate max-w-20
  `.trim();

  const containerClasses = `
    flex items-center gap-2
    ${labelPosition === 'bottom' ? 'flex-col' : 'flex-row'}
    ${onClick ? 'cursor-pointer' : ''}
    ${className}
  `.trim();

  return (
    <div className={containerClasses} onClick={onClick}>
      <CategoryIcon 
        category={category}
        size={size}
        variant={variant}
        isDark={isDark}
        showBackground={true}
      />
      {showLabel && (
        <span 
          className={labelClasses}
          style={{ color: colors.text }}
          title={config.name}
        >
          {config.name}
        </span>
      )}
    </div>
  );
};

// Category Badge (for tags and chips)
export const CategoryBadge = ({ 
  category, 
  size = 'sm',
  removable = false,
  onRemove = null,
  className = '',
  isDark = false,
  onClick = null
}) => {
  const config = getCategoryConfig(category);
  const colors = getCategoryColors(category, isDark);
  const IconComponent = config.icon;

  const sizeConfig = {
    xs: {
      padding: 'px-2 py-1',
      text: 'text-xs',
      icon: 'h-3 w-3'
    },
    sm: {
      padding: 'px-3 py-1.5',
      text: 'text-sm',
      icon: 'h-4 w-4'
    },
    md: {
      padding: 'px-4 py-2',
      text: 'text-sm',
      icon: 'h-4 w-4'
    }
  };

  const currentSize = sizeConfig[size] || sizeConfig.sm;

  const badgeClasses = `
    inline-flex items-center gap-2 rounded-full font-medium transition-all duration-200
    ${currentSize.padding}
    ${currentSize.text}
    ${onClick ? 'cursor-pointer hover:scale-105' : ''}
    ${className}
  `.trim();

  return (
    <span
      className={badgeClasses}
      style={{
        backgroundColor: colors.secondary,
        color: colors.text,
        border: `1px solid ${colors.border}`
      }}
      onClick={onClick}
    >
      <IconComponent className={currentSize.icon} />
      <span className="truncate">{config.name}</span>
      {removable && onRemove && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onRemove();
          }}
          className="ml-1 hover:bg-red-100 dark:hover:bg-red-900 rounded-full p-0.5 transition-colors"
        >
          <svg className="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      )}
    </span>
  );
};

// Category Color Indicator (small colored dot)
export const CategoryColorIndicator = ({ 
  category, 
  size = 'md',
  className = '',
  isDark = false
}) => {
  const colors = getCategoryColors(category, isDark);
  
  const sizeClasses = {
    xs: 'h-2 w-2',
    sm: 'h-3 w-3', 
    md: 'h-4 w-4',
    lg: 'h-5 w-5',
    xl: 'h-6 w-6'
  };

  return (
    <div
      className={`
        rounded-full border-2 border-white dark:border-gray-800 shadow-sm
        ${sizeClasses[size] || sizeClasses.md}
        ${className}
      `}
      style={{ backgroundColor: colors.primary }}
    />
  );
};

export default CategoryIcon;
