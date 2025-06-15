import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
  MagnifyingGlassIcon,
  XMarkIcon,
  ClockIcon,
  FunnelIcon,
  CalendarIcon,
  CurrencyDollarIcon,
  TagIcon,
  ArrowRightIcon,
  CommandLineIcon
} from '@heroicons/react/24/outline';
import { useCurrency } from '../../context/CurrencyContext';
import { useTheme } from '../../context/ThemeContext';

const UniversalSearch = ({
  onSearch,
  onNavigate,
  isOpen,
  onClose,
  data = {
    expenses: [],
    income: [],
    budgets: [],
    categories: []
  }
}) => {
  const { formatAmount } = useCurrency();
  const { isDark } = useTheme();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState({
    type: 'all', // all, expenses, income, budgets
    dateRange: 'all', // all, week, month, year
    amountRange: 'all', // all, low, medium, high
    category: 'all'
  });
  const [recentSearches, setRecentSearches] = useState([]);
  
  const searchInputRef = useRef(null);
  const resultsRef = useRef(null);

  // Load recent searches from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('universalSearchRecent');
    if (saved) {
      try {
        setRecentSearches(JSON.parse(saved));
      } catch (error) {
        console.error('Error loading recent searches:', error);
      }
    }
  }, []);

  // Save recent searches to localStorage
  const saveRecentSearch = useCallback((term) => {
    if (!term.trim()) return;
    
    const updated = [term, ...recentSearches.filter(s => s !== term)].slice(0, 5);
    setRecentSearches(updated);
    localStorage.setItem('universalSearchRecent', JSON.stringify(updated));
  }, [recentSearches]);

  // Focus search input when opened
  useEffect(() => {
    if (isOpen && searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [isOpen]);

  // Filter and search data
  const searchResults = useMemo(() => {
    if (!searchTerm.trim()) return [];

    const term = searchTerm.toLowerCase();
    const results = [];

    // Helper function to check date range
    const isInDateRange = (date) => {
      if (filters.dateRange === 'all') return true;
      const itemDate = new Date(date);
      const now = new Date();
      
      switch (filters.dateRange) {
        case 'week':
          return (now - itemDate) <= 7 * 24 * 60 * 60 * 1000;
        case 'month':
          return (now - itemDate) <= 30 * 24 * 60 * 60 * 1000;
        case 'year':
          return (now - itemDate) <= 365 * 24 * 60 * 60 * 1000;
        default:
          return true;
      }
    };

    // Helper function to check amount range
    const isInAmountRange = (amount) => {
      if (filters.amountRange === 'all') return true;
      
      switch (filters.amountRange) {
        case 'low':
          return amount <= 1000;
        case 'medium':
          return amount > 1000 && amount <= 10000;
        case 'high':
          return amount > 10000;
        default:
          return true;
      }
    };

    // Search expenses
    if (filters.type === 'all' || filters.type === 'expenses') {
      data.expenses?.forEach(expense => {
        const matches = 
          expense.title?.toLowerCase().includes(term) ||
          expense.description?.toLowerCase().includes(term) ||
          expense.category?.toLowerCase().includes(term);
        
        if (matches && 
            isInDateRange(expense.date) && 
            isInAmountRange(expense.amount) &&
            (filters.category === 'all' || expense.category === filters.category)) {
          results.push({
            ...expense,
            type: 'expense',
            icon: CurrencyDollarIcon,
            color: 'text-red-600 dark:text-red-400',
            bgColor: 'bg-red-50 dark:bg-red-900/20',
            route: '/expenses'
          });
        }
      });
    }

    // Search income
    if (filters.type === 'all' || filters.type === 'income') {
      data.income?.forEach(income => {
        const matches = 
          income.title?.toLowerCase().includes(term) ||
          income.description?.toLowerCase().includes(term) ||
          income.source?.toLowerCase().includes(term);
        
        if (matches && 
            isInDateRange(income.date) && 
            isInAmountRange(income.amount)) {
          results.push({
            ...income,
            type: 'income',
            icon: ArrowRightIcon,
            color: 'text-green-600 dark:text-green-400',
            bgColor: 'bg-green-50 dark:bg-green-900/20',
            route: '/income'
          });
        }
      });
    }

    // Search budgets
    if (filters.type === 'all' || filters.type === 'budgets') {
      data.budgets?.forEach(budget => {
        const matches = 
          budget.name?.toLowerCase().includes(term) ||
          budget.category?.toLowerCase().includes(term);
        
        if (matches &&
            (filters.category === 'all' || budget.category === filters.category)) {
          results.push({
            ...budget,
            type: 'budget',
            icon: FunnelIcon,
            color: 'text-blue-600 dark:text-blue-400',
            bgColor: 'bg-blue-50 dark:bg-blue-900/20',
            route: '/budgets'
          });
        }
      });
    }

    return results.slice(0, 10); // Limit to 10 results
  }, [searchTerm, filters, data]);

  // Handle keyboard navigation
  const handleKeyDown = useCallback((e) => {
    if (!isOpen) return;

    switch (e.key) {
      case 'Escape':
        onClose();
        break;
      case 'ArrowDown':
        e.preventDefault();
        setSelectedIndex(prev => 
          prev < searchResults.length - 1 ? prev + 1 : 0
        );
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedIndex(prev => 
          prev > 0 ? prev - 1 : searchResults.length - 1
        );
        break;
      case 'Enter':
        e.preventDefault();
        if (searchResults[selectedIndex]) {
          handleResultSelect(searchResults[selectedIndex]);
        } else if (searchTerm.trim()) {
          handleSearch();
        }
        break;
      default:
        break;
    }
  }, [isOpen, searchResults, selectedIndex, searchTerm, onClose]);

  // Add keyboard event listener
  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  const handleSearch = useCallback(() => {
    if (searchTerm.trim()) {
      saveRecentSearch(searchTerm);
      onSearch?.(searchTerm, filters);
      onClose();
    }
  }, [searchTerm, filters, onSearch, onClose, saveRecentSearch]);

  const handleResultSelect = useCallback((result) => {
    saveRecentSearch(searchTerm);
    onNavigate?.(result.route, result);
    onClose();
  }, [searchTerm, onNavigate, onClose, saveRecentSearch]);

  const clearSearch = () => {
    setSearchTerm('');
    setSelectedIndex(0);
    searchInputRef.current?.focus();
  };

  const clearRecentSearches = () => {
    setRecentSearches([]);
    localStorage.removeItem('universalSearchRecent');
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      {/* Backdrop - Subtle overlay without blur */}
      <div
        className="fixed inset-0 bg-black/25 transition-opacity"
        style={{
          animation: 'searchBackdropFadeIn 0.15s ease-out forwards'
        }}
        onClick={onClose}
      />

      {/* Search Modal - Positioned with proper gap from navbar */}
      <div className="flex min-h-full items-start justify-center px-4 pt-20">
        <div
          className="w-full max-w-2xl bg-white dark:bg-gray-800 rounded-xl shadow-2xl border border-gray-200 dark:border-gray-700 overflow-hidden ring-1 ring-black/5 dark:ring-white/10 transform transition-all duration-200 ease-out"
          style={{
            animation: 'searchModalSlideIn 0.2s ease-out forwards',
            marginTop: '2rem'
          }}
        >
          {/* Search Input - Enhanced design matching screenshot */}
          <div className="flex items-center px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <MagnifyingGlassIcon className="h-5 w-5 text-gray-400 dark:text-gray-500 mr-4 flex-shrink-0" />
            <input
              ref={searchInputRef}
              type="text"
              placeholder="Search expenses, income, budgets..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="flex-1 bg-transparent text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 text-lg font-medium focus:outline-none"
            />
            <div className="flex items-center space-x-2 ml-4">
              <kbd className="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 rounded text-sm font-medium border border-gray-300 dark:border-gray-600">
                /
              </kbd>
              <button
                onClick={() => setShowFilters(!showFilters)}
                className={`p-2 rounded-lg transition-all duration-200 ${
                  showFilters
                    ? 'bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400'
                    : 'text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                }`}
                title="Filters"
              >
                <FunnelIcon className="h-4 w-4" />
              </button>
              {searchTerm && (
                <button
                  onClick={clearSearch}
                  className="p-2 rounded-lg text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-all duration-200"
                  title="Clear search"
                >
                  <XMarkIcon className="h-4 w-4" />
                </button>
              )}
            </div>
          </div>

          {/* Filters - More compact */}
          {showFilters && (
            <div className="px-4 py-2 bg-gray-50 dark:bg-gray-700/50 border-b border-gray-200 dark:border-gray-700">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <select
                  value={filters.type}
                  onChange={(e) => setFilters(prev => ({ ...prev, type: e.target.value }))}
                  className="text-xs py-1 px-2 rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="all">All Types</option>
                  <option value="expenses">Expenses</option>
                  <option value="income">Income</option>
                  <option value="budgets">Budgets</option>
                </select>

                <select
                  value={filters.dateRange}
                  onChange={(e) => setFilters(prev => ({ ...prev, dateRange: e.target.value }))}
                  className="text-xs py-1 px-2 rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="all">All Time</option>
                  <option value="week">This Week</option>
                  <option value="month">This Month</option>
                  <option value="year">This Year</option>
                </select>

                <select
                  value={filters.amountRange}
                  onChange={(e) => setFilters(prev => ({ ...prev, amountRange: e.target.value }))}
                  className="text-xs py-1 px-2 rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="all">All Amounts</option>
                  <option value="low">Under ₹1,000</option>
                  <option value="medium">₹1,000 - ₹10,000</option>
                  <option value="high">Over ₹10,000</option>
                </select>

                <select
                  value={filters.category}
                  onChange={(e) => setFilters(prev => ({ ...prev, category: e.target.value }))}
                  className="text-xs py-1 px-2 rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="all">All Categories</option>
                  {data.categories?.map(category => (
                    <option key={category} value={category}>{category}</option>
                  ))}
                </select>
              </div>
            </div>
          )}

          {/* Results - More compact height */}
          <div ref={resultsRef} className="max-h-80 overflow-y-auto">
            {searchTerm.trim() ? (
              searchResults.length > 0 ? (
                <div className="py-1">
                  {searchResults.map((result, index) => (
                    <button
                      key={`${result.type}-${result._id || result.id || index}`}
                      onClick={() => handleResultSelect(result)}
                      className={`w-full px-4 py-3 text-left hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-all duration-200 rounded-lg mx-2 interactive-card ${
                        index === selectedIndex ? 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-700' : ''
                      }`}
                      style={{
                        transform: 'scale(1)',
                        transition: 'all 200ms ease-in-out'
                      }}
                      onMouseEnter={(e) => {
                        e.target.style.transform = 'scale(1.01)';
                        e.target.style.boxShadow = '0 2px 8px rgba(59, 130, 246, 0.1)';
                      }}
                      onMouseLeave={(e) => {
                        e.target.style.transform = 'scale(1)';
                        e.target.style.boxShadow = '';
                      }}
                    >
                      <div className="flex items-center space-x-2">
                        <div className={`p-1.5 rounded-md ${result.bgColor}`}>
                          <result.icon className={`h-3 w-3 ${result.color}`} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                              {result.title || result.name}
                            </p>
                            <span className="text-sm text-gray-500 dark:text-gray-400 ml-2 flex-shrink-0">
                              {formatAmount(result.amount || result.limit, { showSymbol: true })}
                            </span>
                          </div>
                          <div className="flex items-center space-x-2 mt-0.5">
                            <span className={`text-xs px-1.5 py-0.5 rounded ${result.bgColor} ${result.color} font-medium`}>
                              {result.type}
                            </span>
                            {result.category && (
                              <span className="text-xs text-gray-500 dark:text-gray-400 truncate">
                                {result.category}
                              </span>
                            )}
                            {result.date && (
                              <span className="text-xs text-gray-400 dark:text-gray-500">
                                {new Date(result.date).toLocaleDateString('en-IN', { month: 'short', day: 'numeric' })}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              ) : (
                <div className="py-6 text-center text-gray-500 dark:text-gray-400">
                  <MagnifyingGlassIcon className="h-6 w-6 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No results found for "{searchTerm}"</p>
                  <p className="text-xs mt-1">Try adjusting your search or filters</p>
                </div>
              )
            ) : (
              <div className="py-2">
                {recentSearches.length > 0 && (
                  <div className="px-3 mb-3">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="text-xs font-medium text-gray-900 dark:text-white">Recent Searches</h3>
                      <button
                        onClick={clearRecentSearches}
                        className="text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
                      >
                        Clear
                      </button>
                    </div>
                    <div className="space-y-0.5">
                      {recentSearches.slice(0, 3).map((search, index) => (
                        <button
                          key={index}
                          onClick={() => setSearchTerm(search)}
                          className="flex items-center space-x-2 w-full px-2 py-1 text-left text-xs text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-50 dark:hover:bg-gray-700/50 rounded transition-colors"
                        >
                          <ClockIcon className="h-3 w-3" />
                          <span className="truncate">{search}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                <div className="px-3 py-2 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
                  <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
                    <div className="flex items-center space-x-2">
                      <span className="flex items-center space-x-1">
                        <CommandLineIcon className="h-3 w-3" />
                        <span>Ctrl+K</span>
                      </span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span>↑↓ navigate</span>
                      <span>Enter select</span>
                      <span>Esc close</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default UniversalSearch;
