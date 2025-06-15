import React, { createContext, useContext, useEffect, useState } from 'react';
import { useAuth } from './AuthContext';
import { authService } from '../services/authService';
import toast from 'react-hot-toast';

const CurrencyContext = createContext();

// Currency configuration with symbols and formatting
export const CURRENCIES = {
  INR: {
    code: 'INR',
    symbol: '₹',
    name: 'Indian Rupee',
    locale: 'en-IN',
  },
  USD: {
    code: 'USD',
    symbol: '$',
    name: 'US Dollar',
    locale: 'en-US',
  },
  EUR: {
    code: 'EUR',
    symbol: '€',
    name: 'Euro',
    locale: 'en-EU',
  },
  GBP: {
    code: 'GBP',
    symbol: '£',
    name: 'British Pound',
    locale: 'en-GB',
  },
  JPY: {
    code: 'JPY',
    symbol: '¥',
    name: 'Japanese Yen',
    locale: 'ja-JP',
  },
  CAD: {
    code: 'CAD',
    symbol: 'C$',
    name: 'Canadian Dollar',
    locale: 'en-CA',
  },
  AUD: {
    code: 'AUD',
    symbol: 'A$',
    name: 'Australian Dollar',
    locale: 'en-AU',
  },
  CNY: {
    code: 'CNY',
    symbol: '¥',
    name: 'Chinese Yuan',
    locale: 'zh-CN',
  },
};

export const CurrencyProvider = ({ children }) => {
  const { user, updateUser, isAuthenticated } = useAuth();
  const [currency, setCurrency] = useState(() => {
    // Get currency from user profile or localStorage fallback
    const savedCurrency = localStorage.getItem('currency');
    return savedCurrency || 'INR';
  });
  const [isUpdating, setIsUpdating] = useState(false);

  // Update currency when user changes
  useEffect(() => {
    if (isAuthenticated && user?.currency) {
      setCurrency(user.currency);
      localStorage.setItem('currency', user.currency);
    }
  }, [user, isAuthenticated]);

  // Save currency to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem('currency', currency);
  }, [currency]);

  const updateCurrency = async (newCurrency) => {
    if (!CURRENCIES[newCurrency]) {
      toast.error('Invalid currency selected');
      return false;
    }

    try {
      setIsUpdating(true);
      
      if (isAuthenticated) {
        // Update currency in backend if user is authenticated
        const response = await authService.updateProfile({ currency: newCurrency });
        updateUser(response.data);
        toast.success(`Currency updated to ${CURRENCIES[newCurrency].name}`);
      } else {
        // Just update localStorage if not authenticated
        localStorage.setItem('currency', newCurrency);
        toast.success(`Currency set to ${CURRENCIES[newCurrency].name}`);
      }
      
      setCurrency(newCurrency);
      return true;
    } catch (error) {
      console.error('Error updating currency:', error);
      toast.error('Failed to update currency');
      return false;
    } finally {
      setIsUpdating(false);
    }
  };

  const formatAmount = (amount, options = {}) => {
    const {
      showSymbol = true,
      showCode = false,
      minimumFractionDigits = 2,
      maximumFractionDigits = 2,
    } = options;

    const currencyInfo = CURRENCIES[currency];
    const numericAmount = typeof amount === 'string' ? parseFloat(amount) : amount;

    if (isNaN(numericAmount)) {
      return showSymbol ? `${currencyInfo.symbol}0.00` : '0.00';
    }

    // Format the number according to locale
    const formattedNumber = new Intl.NumberFormat(currencyInfo.locale, {
      minimumFractionDigits,
      maximumFractionDigits,
    }).format(Math.abs(numericAmount));

    let result = '';
    
    if (showSymbol) {
      result = `${currencyInfo.symbol}${formattedNumber}`;
    } else {
      result = formattedNumber;
    }

    if (showCode) {
      result += ` ${currencyInfo.code}`;
    }

    // Add negative sign if needed
    if (numericAmount < 0) {
      result = `-${result}`;
    }

    return result;
  };

  const getCurrencySymbol = (currencyCode = currency) => {
    return CURRENCIES[currencyCode]?.symbol || '$';
  };

  const getCurrencyInfo = (currencyCode = currency) => {
    return CURRENCIES[currencyCode] || CURRENCIES.INR;
  };

  const value = {
    currency,
    currencyInfo: getCurrencyInfo(),
    currencies: CURRENCIES,
    isUpdating,
    updateCurrency,
    formatAmount,
    getCurrencySymbol,
    getCurrencyInfo,
  };

  return (
    <CurrencyContext.Provider value={value}>
      {children}
    </CurrencyContext.Provider>
  );
};

export const useCurrency = () => {
  const context = useContext(CurrencyContext);
  if (!context) {
    throw new Error('useCurrency must be used within a CurrencyProvider');
  }
  return context;
};
