import React from 'react';
import { useCurrency } from '../../context/CurrencyContext';

const CurrencyDisplay = ({ 
  amount, 
  className = '', 
  showSymbol = true, 
  showCode = false,
  compact = false,
  minimumFractionDigits = 2,
  maximumFractionDigits = 2,
  variant = 'default',
  size = 'md'
}) => {
  const { formatAmount } = useCurrency();

  const sizeClasses = {
    xs: 'text-xs',
    sm: 'text-sm',
    md: 'text-base',
    lg: 'text-lg',
    xl: 'text-xl',
    '2xl': 'text-2xl',
  };

  const variantClasses = {
    default: 'text-gray-900 dark:text-white',
    success: 'text-green-600 dark:text-green-400',
    danger: 'text-red-600 dark:text-red-400',
    warning: 'text-yellow-600 dark:text-yellow-400',
    info: 'text-blue-600 dark:text-blue-400',
    muted: 'text-gray-500 dark:text-gray-400',
  };

  const formattedAmount = formatAmount(amount, {
    showSymbol,
    showCode,
    minimumFractionDigits,
    maximumFractionDigits,
  });

  // Determine variant based on amount if not specified
  let finalVariant = variant;
  if (variant === 'auto') {
    const numericAmount = typeof amount === 'string' ? parseFloat(amount) : amount;
    if (numericAmount > 0) {
      finalVariant = 'success';
    } else if (numericAmount < 0) {
      finalVariant = 'danger';
    } else {
      finalVariant = 'default';
    }
  }

  return (
    <span 
      className={`
        font-medium
        ${sizeClasses[size]}
        ${variantClasses[finalVariant]}
        ${className}
      `}
      title={`${formattedAmount} ${showCode ? '' : '(' + formatAmount(amount, { showSymbol: false, showCode: true }) + ')'}`}
    >
      {formattedAmount}
    </span>
  );
};

export default CurrencyDisplay;
