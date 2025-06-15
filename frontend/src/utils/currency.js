import { CURRENCIES } from '../context/CurrencyContext';

/**
 * Format amount with currency symbol
 * @param {number|string} amount - The amount to format
 * @param {string} currencyCode - Currency code (e.g., 'INR', 'USD')
 * @param {object} options - Formatting options
 * @returns {string} Formatted currency string
 */
export const formatCurrency = (amount, currencyCode = 'INR', options = {}) => {
  const {
    showSymbol = true,
    showCode = false,
    minimumFractionDigits = 2,
    maximumFractionDigits = 2,
    compact = false,
  } = options;

  const currencyInfo = CURRENCIES[currencyCode] || CURRENCIES.INR;
  const numericAmount = typeof amount === 'string' ? parseFloat(amount) : amount;

  if (isNaN(numericAmount)) {
    return showSymbol ? `${currencyInfo.symbol}0.00` : '0.00';
  }

  // Handle compact formatting for large numbers
  if (compact && Math.abs(numericAmount) >= 1000) {
    return formatCompactCurrency(numericAmount, currencyCode, options);
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

/**
 * Format large amounts in compact form (e.g., 1.2K, 1.5M)
 * @param {number} amount - The amount to format
 * @param {string} currencyCode - Currency code
 * @param {object} options - Formatting options
 * @returns {string} Compact formatted currency string
 */
export const formatCompactCurrency = (amount, currencyCode = 'INR', options = {}) => {
  const { showSymbol = true } = options;
  const currencyInfo = CURRENCIES[currencyCode] || CURRENCIES.INR;
  const absAmount = Math.abs(amount);
  
  let formattedAmount;
  let suffix = '';

  if (absAmount >= 1e9) {
    formattedAmount = (absAmount / 1e9).toFixed(1);
    suffix = 'B';
  } else if (absAmount >= 1e6) {
    formattedAmount = (absAmount / 1e6).toFixed(1);
    suffix = 'M';
  } else if (absAmount >= 1e3) {
    formattedAmount = (absAmount / 1e3).toFixed(1);
    suffix = 'K';
  } else {
    formattedAmount = absAmount.toFixed(0);
  }

  // Remove unnecessary .0
  formattedAmount = formattedAmount.replace(/\.0$/, '');

  let result = showSymbol 
    ? `${currencyInfo.symbol}${formattedAmount}${suffix}`
    : `${formattedAmount}${suffix}`;

  // Add negative sign if needed
  if (amount < 0) {
    result = `-${result}`;
  }

  return result;
};

/**
 * Get currency symbol for a given currency code
 * @param {string} currencyCode - Currency code
 * @returns {string} Currency symbol
 */
export const getCurrencySymbol = (currencyCode = 'INR') => {
  return CURRENCIES[currencyCode]?.symbol || '₹';
};

/**
 * Get currency information
 * @param {string} currencyCode - Currency code
 * @returns {object} Currency information object
 */
export const getCurrencyInfo = (currencyCode = 'INR') => {
  return CURRENCIES[currencyCode] || CURRENCIES.INR;
};

/**
 * Parse currency string to number
 * @param {string} currencyString - Currency string to parse
 * @returns {number} Parsed number
 */
export const parseCurrency = (currencyString) => {
  if (typeof currencyString === 'number') {
    return currencyString;
  }
  
  // Remove currency symbols and spaces, keep only numbers, dots, and minus
  const cleanString = currencyString.replace(/[^\d.-]/g, '');
  const parsed = parseFloat(cleanString);
  
  return isNaN(parsed) ? 0 : parsed;
};

/**
 * Validate if a string is a valid currency code
 * @param {string} code - Currency code to validate
 * @returns {boolean} True if valid currency code
 */
export const isValidCurrencyCode = (code) => {
  return Object.keys(CURRENCIES).includes(code);
};

/**
 * Get list of all supported currencies
 * @returns {Array} Array of currency objects
 */
export const getSupportedCurrencies = () => {
  return Object.entries(CURRENCIES).map(([code, info]) => ({
    code,
    ...info,
  }));
};
