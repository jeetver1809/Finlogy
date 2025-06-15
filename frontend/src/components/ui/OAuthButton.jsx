import React from 'react';
import LoadingSpinner from './LoadingSpinner';

const OAuthButton = ({ 
  provider, 
  onClick, 
  isLoading = false, 
  disabled = false,
  className = '',
  children 
}) => {
  const getProviderStyles = () => {
    switch (provider) {
      case 'google':
        return {
          bg: 'bg-white hover:bg-gray-50 dark:bg-gray-800 dark:hover:bg-gray-700',
          border: 'border border-gray-300 dark:border-gray-600 hover:border-blue-300 dark:hover:border-blue-500',
          text: 'text-gray-700 dark:text-gray-200',
          shadow: 'shadow-sm hover:shadow-lg',
          hoverEffect: 'hover:scale-[1.02] hover:shadow-blue-100 dark:hover:shadow-blue-900/20',
          icon: (
            <svg className="w-5 h-5" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
              />
            </svg>
          )
        };
      default:
        return {
          bg: 'bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600',
          border: 'border border-gray-300 dark:border-gray-600',
          text: 'text-gray-700 dark:text-gray-200',
          shadow: 'shadow-sm hover:shadow-md',
          hoverEffect: 'hover:scale-[1.02]',
          icon: null
        };
    }
  };

  const styles = getProviderStyles();

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled || isLoading}
      className={`
        w-full flex items-center justify-center px-4 py-3 rounded-lg font-medium text-sm
        transition-all duration-200 ease-in-out
        focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 dark:focus:ring-offset-gray-900
        disabled:opacity-50 disabled:cursor-not-allowed
        transform active:scale-[0.98]
        ${styles.bg} ${styles.border} ${styles.text} ${styles.shadow} ${styles.hoverEffect}
        ${className}
      `}
    >
      {isLoading ? (
        <LoadingSpinner size="sm" className="mr-3" />
      ) : (
        styles.icon && <span className="mr-3">{styles.icon}</span>
      )}
      {children}
    </button>
  );
};

export default OAuthButton;
