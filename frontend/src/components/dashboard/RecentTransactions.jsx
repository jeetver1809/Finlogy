import React, { useState } from 'react';
import { format } from 'date-fns';
import { ArrowUpIcon, ArrowDownIcon, EyeIcon, ClockIcon } from '@heroicons/react/24/outline';
import { useCurrency } from '../../context/CurrencyContext';

const RecentTransactions = ({ transactions = [], expenses = [], income = [], onViewAll, onTransactionClick }) => {
  const [hoveredTransaction, setHoveredTransaction] = useState(null);
  const { formatAmount } = useCurrency();

  // Use transactions prop if provided, otherwise combine expenses and income
  const allTransactions = transactions.length > 0
    ? transactions.sort((a, b) => new Date(b.date) - new Date(a.date))
    : [
        ...expenses.map(expense => ({ ...expense, type: 'expense' })),
        ...income.map(incomeItem => ({ ...incomeItem, type: 'income' })),
      ].sort((a, b) => new Date(b.date) - new Date(a.date));



  if (allTransactions.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center space-x-3 mb-4">
          <div className="p-2 bg-blue-100 dark:bg-blue-900/50 rounded-lg">
            <ClockIcon className="h-5 w-5 text-blue-600 dark:text-blue-400" />
          </div>
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
            Recent Transactions
          </h3>
        </div>
        <div className="text-center py-8">
          <ClockIcon className="h-12 w-12 text-gray-400 dark:text-gray-500 mx-auto mb-3" />
          <p className="text-gray-500 dark:text-gray-400">No recent transactions</p>
          <p className="text-gray-400 dark:text-gray-500 text-sm mt-1">
            Your recent transactions will appear here
          </p>
        </div>
      </div>
    );
  }

  const getCategoryColor = (category, type) => {
    if (type === 'income') {
      return 'text-green-600 bg-green-100 dark:text-green-400 dark:bg-green-900/20';
    }
    
    const colors = {
      food: 'text-orange-600 bg-orange-100 dark:text-orange-400 dark:bg-orange-900/20',
      transportation: 'text-blue-600 bg-blue-100 dark:text-blue-400 dark:bg-blue-900/20',
      utilities: 'text-purple-600 bg-purple-100 dark:text-purple-400 dark:bg-purple-900/20',
      entertainment: 'text-pink-600 bg-pink-100 dark:text-pink-400 dark:bg-pink-900/20',
      healthcare: 'text-red-600 bg-red-100 dark:text-red-400 dark:bg-red-900/20',
      shopping: 'text-indigo-600 bg-indigo-100 dark:text-indigo-400 dark:bg-indigo-900/20',
    };
    
    return colors[category] || 'text-gray-600 bg-gray-100 dark:text-gray-400 dark:bg-gray-900/20';
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700">
      {/* Header */}
      <div className="p-6 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-blue-100 dark:bg-blue-900/50 rounded-lg">
              <ClockIcon className="h-5 w-5 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                Recent Transactions
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Last {Math.min(allTransactions.length, 5)} transactions
              </p>
            </div>
          </div>

          {onViewAll && allTransactions.length > 0 && (
            <button
              onClick={onViewAll}
              className="flex items-center space-x-1 text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
            >
              <EyeIcon className="h-4 w-4" />
              <span>View All</span>
            </button>
          )}
        </div>
      </div>

      {/* Transactions List */}
      <div className="p-6">
        <div className="space-y-3">
      {allTransactions.slice(0, 5).map((transaction, index) => {
        const isHovered = hoveredTransaction === `${transaction.type}-${transaction._id}`;

        return (
          <div
            key={`${transaction.type}-${transaction._id}`}
            className={`
              transaction-item p-3 rounded-lg cursor-pointer
              bg-gray-50 dark:bg-gray-700/50
              border border-transparent
              ${isHovered ? 'border-blue-200 dark:border-blue-700' : ''}
              transition-colors duration-200 ease-in-out
            `}
            onMouseEnter={() => setHoveredTransaction(`${transaction.type}-${transaction._id}`)}
            onMouseLeave={() => setHoveredTransaction(null)}
            onClick={() => onTransactionClick?.(transaction)}
            style={{
              animationDelay: `${index * 50}ms`
            }}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className={`
                  p-2 rounded-full transition-colors duration-200 ease-in-out
                  ${getCategoryColor(transaction.category || transaction.source, transaction.type)}
                `}>
                  {transaction.type === 'income' ? (
                    <ArrowUpIcon className="h-4 w-4" />
                  ) : (
                    <ArrowDownIcon className="h-4 w-4" />
                  )}
                </div>
                <div>
                  <p className="font-medium text-gray-900 dark:text-white">
                    {transaction.title}
                  </p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    {transaction.type === 'income' ? transaction.source : transaction.category} •{' '}
                    {format(new Date(transaction.date), 'MMM dd')}
                  </p>
                  {transaction.description && isHovered && (
                    <p className="text-xs text-gray-400 dark:text-gray-500 mt-1 opacity-0 animate-slide-in-up">
                      {transaction.description}
                    </p>
                  )}
                </div>
              </div>
              <div className="text-right flex items-center space-x-2">
                <div>
                  <p className={`
                    font-medium
                    ${transaction.type === 'income'
                      ? 'text-green-600 dark:text-green-400'
                      : 'text-red-600 dark:text-red-400'
                    }
                  `}>
                    {transaction.type === 'income' ? '+' : '-'}{formatAmount(transaction.amount, { showSymbol: true })}
                  </p>
                  {transaction.paymentMethod && isHovered && (
                    <p className="text-xs text-gray-400 dark:text-gray-500 opacity-0 animate-slide-in-up">
                      {transaction.paymentMethod}
                    </p>
                  )}
                </div>
                {isHovered && (
                  <div className="opacity-0 animate-slide-in-up">
                    <EyeIcon className="h-4 w-4 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300" />
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })}

        </div>
      </div>

      {/* Footer */}
      {allTransactions.length > 5 && (
        <div className="px-6 py-3 bg-gray-50 dark:bg-gray-700/50 border-t border-gray-200 dark:border-gray-700 rounded-b-lg">
          <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
            <span>
              Showing 5 of {allTransactions.length} transactions
            </span>
            {onViewAll && (
              <button
                onClick={onViewAll}
                className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
              >
                View all transactions →
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default RecentTransactions;
