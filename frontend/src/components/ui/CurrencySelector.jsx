import React, { useState } from 'react';
import { ChevronDownIcon, CheckIcon } from '@heroicons/react/24/outline';
import { useCurrency } from '../../context/CurrencyContext';

const CurrencySelector = ({ 
  className = '', 
  showLabel = true, 
  size = 'md',
  variant = 'default' 
}) => {
  const { currency, currencies, updateCurrency, isUpdating } = useCurrency();
  const [isOpen, setIsOpen] = useState(false);

  const handleCurrencyChange = async (newCurrency) => {
    setIsOpen(false);
    if (newCurrency !== currency) {
      await updateCurrency(newCurrency);
    }
  };

  const sizeClasses = {
    sm: 'text-sm px-2 py-1',
    md: 'text-sm px-3 py-2',
    lg: 'text-base px-4 py-3',
  };

  const variantClasses = {
    default: 'bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white hover:bg-gray-50 dark:hover:bg-gray-600',
    minimal: 'bg-transparent border-transparent text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700',
    navbar: 'bg-white dark:bg-gray-700 border-gray-200 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-600',
  };

  return (
    <div className={`relative ${className}`}>
      {showLabel && (
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Currency
        </label>
      )}
      
      <div className="relative">
        <button
          type="button"
          onClick={() => setIsOpen(!isOpen)}
          disabled={isUpdating}
          className={`
            relative w-full border rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors
            ${sizeClasses[size]}
            ${variantClasses[variant]}
            ${isUpdating ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
            flex items-center justify-between
          `}
          aria-haspopup="listbox"
          aria-expanded={isOpen}
        >
          <div className="flex items-center space-x-2">
            <span className="font-medium">{currencies[currency]?.symbol}</span>
            <span className="text-gray-600 dark:text-gray-400">{currencies[currency]?.code}</span>
          </div>
          <ChevronDownIcon
            className={`h-4 w-4 text-gray-400 dark:text-gray-500 transition-transform ${isOpen ? 'rotate-180' : ''}`}
          />
        </button>

        {isOpen && (
          <>
            {/* Backdrop */}
            <div 
              className="fixed inset-0 z-10" 
              onClick={() => setIsOpen(false)}
            />
            
            {/* Dropdown */}
            <div className="absolute z-20 mt-1 w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md shadow-lg max-h-60 overflow-auto">
              <ul className="py-1" role="listbox">
                {Object.entries(currencies).map(([code, currencyInfo]) => (
                  <li key={code} role="option" aria-selected={code === currency}>
                    <button
                      type="button"
                      onClick={() => handleCurrencyChange(code)}
                      className={`
                        w-full text-left px-3 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 focus:outline-none focus:bg-gray-100 dark:focus:bg-gray-700 transition-colors
                        flex items-center justify-between
                        ${code === currency
                          ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300'
                          : 'text-gray-900 dark:text-white'
                        }
                      `}
                    >
                      <div className="flex items-center space-x-3">
                        <span className="font-medium text-lg">{currencyInfo.symbol}</span>
                        <div>
                          <div className="font-medium">{currencyInfo.code}</div>
                          <div className="text-sm text-gray-500 dark:text-gray-400">{currencyInfo.name}</div>
                        </div>
                      </div>
                      {code === currency && (
                        <CheckIcon className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                      )}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default CurrencySelector;
