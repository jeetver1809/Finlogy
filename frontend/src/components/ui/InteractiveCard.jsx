import React from 'react';

/**
 * InteractiveCard - Reusable component with Budget Overview hover effects
 * 
 * Features:
 * - Blue glow hover effect matching Budget Overview
 * - Dark mode support
 * - Customizable styling
 * - Accessibility support
 */
const InteractiveCard = ({ 
  children, 
  className = "", 
  variant = "default", // "default", "subtle", "button"
  onClick,
  disabled = false,
  ...props 
}) => {
  const getVariantClasses = () => {
    switch (variant) {
      case "subtle":
        return "hover-glow-subtle";
      case "button":
        return "btn-glow";
      default:
        return "interactive-card hover-brighten";
    }
  };

  const baseClasses = "bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700";
  const variantClasses = getVariantClasses();
  const disabledClasses = disabled ? "opacity-50 cursor-not-allowed" : "";

  return (
    <div 
      className={`${baseClasses} ${variantClasses} ${disabledClasses} ${className}`}
      onClick={disabled ? undefined : onClick}
      {...props}
    >
      {children}
    </div>
  );
};

/**
 * InteractiveButton - Button with Budget Overview hover effects
 */
export const InteractiveButton = ({ 
  children, 
  className = "", 
  variant = "primary", // "primary", "secondary", "danger"
  size = "md", // "sm", "md", "lg"
  disabled = false,
  ...props 
}) => {
  const getVariantClasses = () => {
    switch (variant) {
      case "secondary":
        return "bg-gray-600 hover:bg-gray-700 dark:bg-gray-700 dark:hover:bg-gray-600 text-white";
      case "danger":
        return "bg-red-600 hover:bg-red-700 dark:bg-red-700 dark:hover:bg-red-800 text-white";
      default:
        return "bg-blue-600 hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-800 text-white";
    }
  };

  const getSizeClasses = () => {
    switch (size) {
      case "sm":
        return "px-3 py-1.5 text-sm";
      case "lg":
        return "px-6 py-3 text-lg";
      default:
        return "px-4 py-2";
    }
  };

  const baseClasses = "rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors font-medium";
  const variantClasses = getVariantClasses();
  const sizeClasses = getSizeClasses();
  const hoverClasses = "btn-glow";
  const disabledClasses = disabled ? "opacity-50 cursor-not-allowed" : "";

  return (
    <button 
      className={`${baseClasses} ${variantClasses} ${sizeClasses} ${hoverClasses} ${disabledClasses} ${className}`}
      disabled={disabled}
      {...props}
    >
      {children}
    </button>
  );
};

/**
 * InteractiveListItem - List item with Budget Overview hover effects
 */
export const InteractiveListItem = ({ 
  children, 
  className = "", 
  onClick,
  disabled = false,
  ...props 
}) => {
  const baseClasses = "p-3 rounded-lg cursor-pointer bg-gray-50 dark:bg-gray-700/50 border border-transparent";
  const hoverClasses = "transaction-item";
  const disabledClasses = disabled ? "opacity-50 cursor-not-allowed" : "";

  return (
    <div 
      className={`${baseClasses} ${hoverClasses} ${disabledClasses} ${className}`}
      onClick={disabled ? undefined : onClick}
      {...props}
    >
      {children}
    </div>
  );
};

/**
 * GlowCard - Simple card with just the glow effect
 */
export const GlowCard = ({ 
  children, 
  className = "", 
  padding = "p-6",
  ...props 
}) => {
  return (
    <div 
      className={`bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 hover-glow ${padding} ${className}`}
      {...props}
    >
      {children}
    </div>
  );
};

export default InteractiveCard;
