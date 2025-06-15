import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
  MagnifyingGlassIcon,
  FunnelIcon,
  XMarkIcon,
  AdjustmentsHorizontalIcon,
  ChevronDownIcon,
  ChevronUpIcon
} from '@heroicons/react/24/outline';
import { useCurrency } from '../../context/CurrencyContext';

const SearchAndFilter = ({
  onSearch,
  onFilter,
  categories = [],
  placeholder = "Search transactions...",
  showAmountFilter = true,
  resultCount = null,
  totalCount = null,
  isLoading = false,
  suggestions = [],
  onSuggestionSelect,
  persistFilters = true,
  filterKey = 'default'
}) => {
  const { getCurrencySymbol } = useCurrency();
  const searchInputRef = useRef(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  const [showMobileFilters, setShowMobileFilters] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [selectedSuggestionIndex, setSelectedSuggestionIndex] = useState(-1);
  const [filters, setFilters] = useState({
    category: '',
    dateFrom: '',
    dateTo: '',
    amountMin: '',
    amountMax: '',
  });

  // Load persisted filters on mount
  useEffect(() => {
    if (persistFilters) {
      const savedFilters = localStorage.getItem(`searchFilters_${filterKey}`);
      const savedSearchTerm = localStorage.getItem(`searchTerm_${filterKey}`);

      if (savedFilters) {
        try {
          setFilters(JSON.parse(savedFilters));
        } catch (error) {
          console.warn('Failed to parse saved filters:', error);
        }
      }

      if (savedSearchTerm) {
        setSearchTerm(savedSearchTerm);
      }
    }
  }, [persistFilters, filterKey]);

  // Debounced search with persistence
  useEffect(() => {
    const timeoutId = setTimeout(() => {
      onSearch(searchTerm);
      if (persistFilters) {
        localStorage.setItem(`searchTerm_${filterKey}`, searchTerm);
      }
    }, 300);

    return () => clearTimeout(timeoutId);
  }, [searchTerm, onSearch, persistFilters, filterKey]);

  // Apply filters when they change with persistence
  useEffect(() => {
    onFilter(filters);
    if (persistFilters) {
      localStorage.setItem(`searchFilters_${filterKey}`, JSON.stringify(filters));
    }
  }, [filters, onFilter, persistFilters, filterKey]);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (event) => {
      // Ctrl+K or Cmd+K to focus search
      if ((event.ctrlKey || event.metaKey) && event.key === 'k') {
        event.preventDefault();
        searchInputRef.current?.focus();
      }

      // Escape to clear search and close suggestions
      if (event.key === 'Escape') {
        if (showSuggestions) {
          setShowSuggestions(false);
          setSelectedSuggestionIndex(-1);
        } else if (searchTerm) {
          setSearchTerm('');
          searchInputRef.current?.focus();
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [searchTerm, showSuggestions]);

  const handleFilterChange = useCallback((key, value) => {
    setFilters(prev => ({
      ...prev,
      [key]: value,
    }));
  }, []);

  const clearFilters = useCallback(() => {
    setFilters({
      category: '',
      dateFrom: '',
      dateTo: '',
      amountMin: '',
      amountMax: '',
    });
    setSearchTerm('');
    setShowSuggestions(false);
    if (persistFilters) {
      localStorage.removeItem(`searchFilters_${filterKey}`);
      localStorage.removeItem(`searchTerm_${filterKey}`);
    }
  }, [persistFilters, filterKey]);

  const handleSearchChange = useCallback((value) => {
    setSearchTerm(value);
    setSelectedSuggestionIndex(-1);

    // Show suggestions if we have them and search term is not empty
    if (suggestions.length > 0 && value.trim()) {
      setShowSuggestions(true);
    } else {
      setShowSuggestions(false);
    }
  }, [suggestions]);

  const handleSuggestionClick = useCallback((suggestion) => {
    setSearchTerm(suggestion);
    setShowSuggestions(false);
    setSelectedSuggestionIndex(-1);
    onSuggestionSelect?.(suggestion);
    searchInputRef.current?.focus();
  }, [onSuggestionSelect]);

  const handleSearchKeyDown = useCallback((event) => {
    if (!showSuggestions || suggestions.length === 0) return;

    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        setSelectedSuggestionIndex(prev =>
          prev < suggestions.length - 1 ? prev + 1 : 0
        );
        break;
      case 'ArrowUp':
        event.preventDefault();
        setSelectedSuggestionIndex(prev =>
          prev > 0 ? prev - 1 : suggestions.length - 1
        );
        break;
      case 'Enter':
        event.preventDefault();
        if (selectedSuggestionIndex >= 0) {
          handleSuggestionClick(suggestions[selectedSuggestionIndex]);
        }
        break;
      case 'Tab':
        if (selectedSuggestionIndex >= 0) {
          event.preventDefault();
          handleSuggestionClick(suggestions[selectedSuggestionIndex]);
        }
        break;
    }
  }, [showSuggestions, suggestions, selectedSuggestionIndex, handleSuggestionClick]);

  const hasActiveFilters = useCallback(() => {
    return Object.values(filters).some(value => value !== '') || searchTerm !== '';
  }, [filters, searchTerm]);

  const getActiveFilterCount = useCallback(() => {
    let count = 0;
    if (searchTerm) count++;
    if (filters.category) count++;
    if (filters.dateFrom || filters.dateTo) count++;
    if (filters.amountMin || filters.amountMax) count++;
    return count;
  }, [filters, searchTerm]);

  // Filter suggestions based on search term
  const filteredSuggestions = useMemo(() => {
    if (!searchTerm.trim() || suggestions.length === 0) return [];

    const searchLower = searchTerm.toLowerCase();
    return suggestions
      .filter(suggestion =>
        suggestion.toLowerCase().includes(searchLower) &&
        suggestion.toLowerCase() !== searchLower
      )
      .slice(0, 5); // Limit to 5 suggestions
  }, [suggestions, searchTerm]);

  // Update suggestions visibility when filtered suggestions change
  useEffect(() => {
    if (filteredSuggestions.length === 0 && showSuggestions) {
      setShowSuggestions(false);
    }
  }, [filteredSuggestions, showSuggestions]);

  const clearSearch = useCallback(() => {
    setSearchTerm('');
    setShowSuggestions(false);
    searchInputRef.current?.focus();
  }, []);

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-4 mb-6">
      {/* Search Bar */}
      <div className="flex flex-col sm:flex-row gap-4 mb-4">
        <div className="flex-1 relative">
          <div className="relative">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400 dark:text-gray-500" />
            <input
              ref={searchInputRef}
              type="text"
              placeholder={`${placeholder} (Ctrl+K)`}
              value={searchTerm}
              onChange={(e) => handleSearchChange(e.target.value)}
              onKeyDown={handleSearchKeyDown}
              onFocus={() => {
                if (filteredSuggestions.length > 0) {
                  setShowSuggestions(true);
                }
              }}
              onBlur={() => {
                // Delay hiding suggestions to allow clicking
                setTimeout(() => setShowSuggestions(false), 150);
              }}
              className="w-full pl-10 pr-12 py-3 min-h-[44px] border border-gray-300 dark:border-gray-600 rounded-lg
                         bg-white dark:bg-gray-700 text-gray-900 dark:text-white
                         focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500
                         transition-colors duration-200"
              disabled={isLoading}
              aria-label="Search transactions"
              aria-expanded={showSuggestions}
              aria-haspopup="listbox"
              role="combobox"
              autoComplete="off"
            />

            {/* Clear button */}
            {searchTerm && (
              <button
                onClick={clearSearch}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 p-1 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300 rounded-full hover:bg-gray-100 dark:hover:bg-gray-600 transition-colors"
                aria-label="Clear search"
                type="button"
              >
                <XMarkIcon className="h-4 w-4" />
              </button>
            )}

            {/* Loading indicator */}
            {isLoading && (
              <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                <div className="animate-spin rounded-full h-4 w-4 border-2 border-blue-500 border-t-transparent"></div>
              </div>
            )}
          </div>

          {/* Search Suggestions */}
          {showSuggestions && filteredSuggestions.length > 0 && (
            <div className="absolute z-50 w-full mt-1 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-600 rounded-lg shadow-lg max-h-60 overflow-y-auto">
              <ul role="listbox" className="py-1">
                {filteredSuggestions.map((suggestion, index) => (
                  <li
                    key={suggestion}
                    role="option"
                    aria-selected={index === selectedSuggestionIndex}
                    className={`px-4 py-2 cursor-pointer transition-colors ${
                      index === selectedSuggestionIndex
                        ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300'
                        : 'text-gray-900 dark:text-white hover:bg-gray-50 dark:hover:bg-gray-700'
                    }`}
                    onClick={() => handleSuggestionClick(suggestion)}
                    onMouseEnter={() => setSelectedSuggestionIndex(index)}
                  >
                    <div className="flex items-center">
                      <MagnifyingGlassIcon className="h-4 w-4 mr-2 text-gray-400" />
                      <span>{suggestion}</span>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <div className="flex gap-2">
          {/* Desktop Filter Button */}
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`hidden sm:flex items-center space-x-2 px-4 py-3 min-h-[44px] border rounded-lg transition-all duration-200 ${
              showFilters || hasActiveFilters()
                ? 'bg-blue-50 dark:bg-blue-900/50 border-blue-300 dark:border-blue-600 text-blue-700 dark:text-blue-300 shadow-sm'
                : 'border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
            }`}
            aria-label={`${showFilters ? 'Hide' : 'Show'} filters`}
            aria-expanded={showFilters}
          >
            <AdjustmentsHorizontalIcon className="h-5 w-5" />
            <span className="font-medium">Filters</span>
            {getActiveFilterCount() > 0 && (
              <span className="bg-blue-600 dark:bg-blue-500 text-white text-xs rounded-full px-2 py-1 min-w-[20px] text-center font-semibold">
                {getActiveFilterCount()}
              </span>
            )}
            {showFilters ? (
              <ChevronUpIcon className="h-4 w-4 ml-1" />
            ) : (
              <ChevronDownIcon className="h-4 w-4 ml-1" />
            )}
          </button>

          {/* Mobile Filter Button */}
          <button
            onClick={() => setShowMobileFilters(true)}
            className={`sm:hidden flex items-center space-x-2 px-4 py-3 min-h-[44px] border rounded-lg transition-all duration-200 ${
              hasActiveFilters()
                ? 'bg-blue-50 dark:bg-blue-900/50 border-blue-300 dark:border-blue-600 text-blue-700 dark:text-blue-300 shadow-sm'
                : 'border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
            }`}
            aria-label="Open filter modal"
          >
            <FunnelIcon className="h-5 w-5" />
            <span className="font-medium">Filter</span>
            {getActiveFilterCount() > 0 && (
              <span className="bg-blue-600 dark:bg-blue-500 text-white text-xs rounded-full px-2 py-1 min-w-[20px] text-center font-semibold">
                {getActiveFilterCount()}
              </span>
            )}
          </button>
          
          {hasActiveFilters() && (
            <button
              onClick={clearFilters}
              className="flex items-center space-x-1 px-3 py-3 min-h-[44px] text-sm text-gray-600 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors border border-gray-300 dark:border-gray-600"
              aria-label="Clear all filters"
            >
              <XMarkIcon className="h-4 w-4" />
              <span className="font-medium">Clear</span>
            </button>
          )}
        </div>
      </div>

      {/* Results Summary */}
      {(resultCount !== null && totalCount !== null) && (
        <div className="flex items-center justify-between mb-4 text-sm">
          <div className="text-gray-600 dark:text-gray-400">
            {resultCount === 0 ? (
              <span className="flex items-center text-amber-600 dark:text-amber-400">
                <svg className="h-4 w-4 mr-1" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
                No results found
              </span>
            ) : (
              <span>
                Showing <span className="font-semibold text-gray-900 dark:text-white">{resultCount}</span> of{' '}
                <span className="font-semibold text-gray-900 dark:text-white">{totalCount}</span> results
              </span>
            )}
          </div>

          {hasActiveFilters() && (
            <button
              onClick={clearFilters}
              className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 font-medium transition-colors"
            >
              Clear all filters
            </button>
          )}
        </div>
      )}

      {/* Desktop Filter Controls */}
      {showFilters && (
        <div className="hidden sm:block border-t border-gray-200 dark:border-gray-600 pt-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {/* Category Filter */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Category
              </label>
              <select
                value={filters.category}
                onChange={(e) => handleFilterChange('category', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                aria-label="Filter by category"
              >
                <option value="">All Categories</option>
                {categories.map(category => (
                  <option key={category} value={category}>
                    {category.charAt(0).toUpperCase() + category.slice(1)}
                  </option>
                ))}
              </select>
            </div>

            {/* Date From */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                From Date
              </label>
              <input
                type="date"
                value={filters.dateFrom}
                onChange={(e) => handleFilterChange('dateFrom', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                aria-label="Filter from date"
              />
            </div>

            {/* Date To */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                To Date
              </label>
              <input
                type="date"
                value={filters.dateTo}
                onChange={(e) => handleFilterChange('dateTo', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                aria-label="Filter to date"
              />
            </div>

            {/* Amount Range */}
            {showAmountFilter && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Amount Range ({getCurrencySymbol()})
                </label>
                <div className="flex space-x-2">
                  <input
                    type="number"
                    placeholder="Min"
                    value={filters.amountMin}
                    onChange={(e) => handleFilterChange('amountMin', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                    min="0"
                    step="0.01"
                    aria-label="Minimum amount"
                  />
                  <input
                    type="number"
                    placeholder="Max"
                    value={filters.amountMax}
                    onChange={(e) => handleFilterChange('amountMax', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                    min="0"
                    step="0.01"
                    aria-label="Maximum amount"
                  />
                </div>
              </div>
            )}
          </div>

          {/* Active Filters Display */}
          {hasActiveFilters() && (
            <div className="mt-6 pt-4 border-t border-gray-200 dark:border-gray-600">
              <div className="flex flex-wrap gap-2">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Active filters:</span>
                {searchTerm && (
                  <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border border-blue-200 dark:border-blue-700">
                    Search: "{searchTerm}"
                    <button
                      onClick={() => setSearchTerm('')}
                      className="ml-1 text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-200"
                      aria-label="Remove search filter"
                    >
                      <XMarkIcon className="h-3 w-3" />
                    </button>
                  </span>
                )}
                {filters.category && (
                  <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/50 text-green-800 dark:text-green-300 border border-green-200 dark:border-green-700">
                    Category: {filters.category.charAt(0).toUpperCase() + filters.category.slice(1)}
                    <button
                      onClick={() => handleFilterChange('category', '')}
                      className="ml-1 text-green-600 dark:text-green-400 hover:text-green-800 dark:hover:text-green-200"
                      aria-label="Remove category filter"
                    >
                      <XMarkIcon className="h-3 w-3" />
                    </button>
                  </span>
                )}
                {(filters.dateFrom || filters.dateTo) && (
                  <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-purple-100 dark:bg-purple-900/50 text-purple-800 dark:text-purple-300 border border-purple-200 dark:border-purple-700">
                    Date: {filters.dateFrom || '...'} to {filters.dateTo || '...'}
                    <button
                      onClick={() => {
                        handleFilterChange('dateFrom', '');
                        handleFilterChange('dateTo', '');
                      }}
                      className="ml-1 text-purple-600 dark:text-purple-400 hover:text-purple-800 dark:hover:text-purple-200"
                      aria-label="Remove date filter"
                    >
                      <XMarkIcon className="h-3 w-3" />
                    </button>
                  </span>
                )}
                {(filters.amountMin || filters.amountMax) && (
                  <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-yellow-100 dark:bg-yellow-900/50 text-yellow-800 dark:text-yellow-300 border border-yellow-200 dark:border-yellow-700">
                    Amount: {getCurrencySymbol()}{filters.amountMin || '0'} - {getCurrencySymbol()}{filters.amountMax || '∞'}
                    <button
                      onClick={() => {
                        handleFilterChange('amountMin', '');
                        handleFilterChange('amountMax', '');
                      }}
                      className="ml-1 text-yellow-600 dark:text-yellow-400 hover:text-yellow-800 dark:hover:text-yellow-200"
                      aria-label="Remove amount filter"
                    >
                      <XMarkIcon className="h-3 w-3" />
                    </button>
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Mobile Filter Modal */}
      {showMobileFilters && (
        <div className="fixed inset-0 z-50 sm:hidden">
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-gray-600 bg-opacity-75 transition-opacity"
            onClick={() => setShowMobileFilters(false)}
          />

          {/* Modal */}
          <div className="fixed inset-x-0 bottom-0 bg-white dark:bg-gray-800 rounded-t-xl shadow-xl transform transition-transform">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-600">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Filters</h3>
              <button
                onClick={() => setShowMobileFilters(false)}
                className="p-2 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700"
                aria-label="Close filters"
              >
                <XMarkIcon className="h-6 w-6" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-4 max-h-96 overflow-y-auto">
              <div className="space-y-6">
                {/* Category Filter */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Category
                  </label>
                  <select
                    value={filters.category}
                    onChange={(e) => handleFilterChange('category', e.target.value)}
                    className="w-full px-3 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="">All Categories</option>
                    {categories.map(category => (
                      <option key={category} value={category}>
                        {category.charAt(0).toUpperCase() + category.slice(1)}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Date Range */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      From Date
                    </label>
                    <input
                      type="date"
                      value={filters.dateFrom}
                      onChange={(e) => handleFilterChange('dateFrom', e.target.value)}
                      className="w-full px-3 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      To Date
                    </label>
                    <input
                      type="date"
                      value={filters.dateTo}
                      onChange={(e) => handleFilterChange('dateTo', e.target.value)}
                      className="w-full px-3 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>
                </div>

                {/* Amount Range */}
                {showAmountFilter && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Amount Range ({getCurrencySymbol()})
                    </label>
                    <div className="grid grid-cols-2 gap-4">
                      <input
                        type="number"
                        placeholder="Min"
                        value={filters.amountMin}
                        onChange={(e) => handleFilterChange('amountMin', e.target.value)}
                        className="w-full px-3 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        min="0"
                        step="0.01"
                      />
                      <input
                        type="number"
                        placeholder="Max"
                        value={filters.amountMax}
                        onChange={(e) => handleFilterChange('amountMax', e.target.value)}
                        className="w-full px-3 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        min="0"
                        step="0.01"
                      />
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-between p-4 border-t border-gray-200 dark:border-gray-600 bg-gray-50 dark:bg-gray-700/50">
              <button
                onClick={clearFilters}
                className="px-4 py-2 text-sm font-medium text-gray-600 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200 transition-colors"
                disabled={!hasActiveFilters()}
              >
                Clear All
              </button>
              <button
                onClick={() => setShowMobileFilters(false)}
                className="px-6 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors"
              >
                Apply Filters
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SearchAndFilter;
export { default as SearchAndFilterSkeleton } from './SearchAndFilterSkeleton';
