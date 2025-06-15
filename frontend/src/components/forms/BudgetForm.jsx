import React, { useState, useEffect } from 'react';
import { XMarkIcon } from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';
import { useCurrency } from '../../context/CurrencyContext';
import { useTheme } from '../../context/ThemeContext';
import { CategoryIconWithLabel } from '../ui/CategoryIcon';
import { getAllCategories } from '../../utils/categoryConfig';

// Get categories from the centralized config
// Map to backend-compatible category names (must match backend Budget model enum)
const BUDGET_CATEGORIES = [
  'food',
  'transportation',
  'utilities',
  'entertainment',
  'healthcare',
  'shopping',
  'education',
  'travel',
  'insurance',
  'housing',
  'personal',
  'business',
  'other',
  'total'
];

// Get category configs for display
const getCategoryDisplayInfo = (categoryKey) => {
  const allCategories = getAllCategories();
  const categoryConfig = allCategories.find(cat => cat.key === categoryKey);
  return categoryConfig || {
    key: categoryKey,
    name: categoryKey.charAt(0).toUpperCase() + categoryKey.slice(1),
    icon: null
  };
};

const BUDGET_PERIODS = [
  'weekly',
  'monthly',
  'yearly',
];

const BudgetForm = ({ isOpen, onClose, onSubmit, budget = null, isLoading = false }) => {
  const { getCurrencySymbol } = useCurrency();
  const { isDark } = useTheme();
  const [formData, setFormData] = useState({
    name: '',
    category: 'food',
    amount: '',
    period: 'monthly',
    startDate: new Date().toISOString().split('T')[0], // Today's date
    alertThreshold: '80',
    description: '',
  });

  const [errors, setErrors] = useState({});

  useEffect(() => {
    if (budget) {
      setFormData({
        name: budget.name || '',
        category: budget.category || 'food',
        amount: budget.amount?.toString() || '',
        period: budget.period || 'monthly',
        startDate: budget.startDate ? new Date(budget.startDate).toISOString().split('T')[0] : new Date().toISOString().split('T')[0],
        alertThreshold: budget.alertThreshold?.toString() || '80',
        description: budget.description || '',
      });
    } else {
      setFormData({
        name: '',
        category: 'food',
        amount: '',
        period: 'monthly',
        startDate: new Date().toISOString().split('T')[0],
        alertThreshold: '80',
        description: '',
      });
    }
    setErrors({});
  }, [budget, isOpen]);

  const validateForm = () => {
    const newErrors = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Budget name is required';
    }

    if (!formData.category || !BUDGET_CATEGORIES.includes(formData.category)) {
      newErrors.category = 'Please select a valid category';
    }

    if (!formData.amount || parseFloat(formData.amount) <= 0) {
      newErrors.amount = 'Amount must be greater than 0';
    }

    if (!formData.alertThreshold || parseFloat(formData.alertThreshold) < 1 || parseFloat(formData.alertThreshold) > 100) {
      newErrors.alertThreshold = 'Alert threshold must be between 1 and 100';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      toast.error('Please fix the errors in the form');
      return;
    }

    try {
      const budgetData = {
        ...formData,
        amount: parseFloat(formData.amount),
        alertThreshold: parseFloat(formData.alertThreshold),
      };

      await onSubmit(budgetData);
      
      if (!budget) {
        // Reset form for new budget
        setFormData({
          name: '',
          category: 'food',
          amount: '',
          period: 'monthly',
          startDate: new Date().toISOString().split('T')[0],
          alertThreshold: '80',
          description: '',
        });
      }
    } catch (error) {
      console.error('Error submitting budget:', error);
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value,
    }));
    
    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: '',
      }));
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 dark:bg-black dark:bg-opacity-70 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-md mx-4 max-h-[90vh] overflow-y-auto border border-gray-200 dark:border-gray-700">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
            {budget ? 'Edit Budget' : 'Create New Budget'}
          </h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300"
            disabled={isLoading}
          >
            <XMarkIcon className="h-6 w-6" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Budget Name *
            </label>
            <input
              type="text"
              name="name"
              value={formData.name}
              onChange={handleChange}
              className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white ${
                errors.name ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
              }`}
              placeholder="Enter budget name"
              disabled={isLoading}
            />
            {errors.name && <p className="text-red-500 dark:text-red-400 text-sm mt-1">{errors.name}</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
              Category *
            </label>

            {/* Visual Category Selection */}
            <div className="grid grid-cols-3 sm:grid-cols-4 gap-3 mb-4">
              {BUDGET_CATEGORIES.filter(cat => cat !== 'total').map(category => {
                const categoryInfo = getCategoryDisplayInfo(category);
                return (
                  <div
                    key={category}
                    onClick={() => setFormData(prev => ({ ...prev, category }))}
                    className={`
                      p-3 rounded-lg border-2 cursor-pointer transition-all duration-200
                      ${formData.category === category
                        ? 'border-purple-500 bg-purple-50 dark:bg-purple-900/20 scale-105'
                        : 'border-gray-200 dark:border-gray-600 hover:border-purple-300 dark:hover:border-purple-400 hover:scale-102'
                      }
                    `}
                  >
                    <CategoryIconWithLabel
                      category={category}
                      size="sm"
                      variant={formData.category === category ? 'filled' : 'soft'}
                      labelPosition="bottom"
                      isDark={isDark}
                      showLabel={true}
                    />
                  </div>
                );
              })}

              {/* Total Budget Option */}
              <div
                onClick={() => setFormData(prev => ({ ...prev, category: 'total' }))}
                className={`
                  p-3 rounded-lg border-2 cursor-pointer transition-all duration-200 col-span-full
                  ${formData.category === 'total'
                    ? 'border-purple-500 bg-purple-50 dark:bg-purple-900/20'
                    : 'border-gray-200 dark:border-gray-600 hover:border-purple-300 dark:hover:border-purple-400'
                  }
                `}
              >
                <div className="flex items-center justify-center space-x-2">
                  <div className={`
                    p-2 rounded-lg transition-all duration-200
                    ${formData.category === 'total'
                      ? 'bg-purple-500 text-white'
                      : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                    }
                  `}>
                    <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 7h6m0 10v-3m-3 3h.01M9 17h.01M9 14h.01M12 14h.01M15 11h.01M12 11h.01M9 11h.01M7 21h10a2 2 0 002-2V5a2 2 0 00-2-2H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                    </svg>
                  </div>
                  <span className={`
                    font-medium
                    ${formData.category === 'total'
                      ? 'text-purple-700 dark:text-purple-300'
                      : 'text-gray-700 dark:text-gray-300'
                    }
                  `}>
                    Total Budget
                  </span>
                </div>
              </div>
            </div>

            {/* Fallback Select for Accessibility */}
            <select
              name="category"
              value={formData.category}
              onChange={handleChange}
              className="sr-only"
              disabled={isLoading}
            >
              {BUDGET_CATEGORIES.map(category => {
                const categoryInfo = getCategoryDisplayInfo(category);
                return (
                  <option key={category} value={category}>
                    {category === 'total' ? 'Total Budget' : categoryInfo.name}
                  </option>
                );
              })}
            </select>

            {/* Category Error Display */}
            {errors.category && (
              <p className="text-red-500 dark:text-red-400 text-sm mt-2">{errors.category}</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Budget Amount ({getCurrencySymbol()}) *
            </label>
            <div className="relative">
              <span className="absolute left-3 top-2 text-gray-500 dark:text-gray-400">{getCurrencySymbol()}</span>
              <input
                type="number"
                name="amount"
                value={formData.amount}
                onChange={handleChange}
                step="0.01"
                min="0"
                className={`w-full pl-8 pr-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white ${
                  errors.amount ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
                }`}
                placeholder="0.00"
                disabled={isLoading}
              />
            </div>
            {errors.amount && <p className="text-red-500 dark:text-red-400 text-sm mt-1">{errors.amount}</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Period *
            </label>
            <select
              name="period"
              value={formData.period}
              onChange={handleChange}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              disabled={isLoading}
            >
              {BUDGET_PERIODS.map(period => (
                <option key={period} value={period}>
                  {period.charAt(0).toUpperCase() + period.slice(1)}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Start Date *
            </label>
            <input
              type="date"
              name="startDate"
              value={formData.startDate}
              onChange={handleChange}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              disabled={isLoading}
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">End date will be calculated automatically based on the period</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Alert Threshold (%) *
            </label>
            <input
              type="number"
              name="alertThreshold"
              value={formData.alertThreshold}
              onChange={handleChange}
              min="1"
              max="100"
              className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white ${
                errors.alertThreshold ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
              }`}
              placeholder="80"
              disabled={isLoading}
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Get notified when you reach this percentage of your budget</p>
            {errors.alertThreshold && <p className="text-red-500 dark:text-red-400 text-sm mt-1">{errors.alertThreshold}</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Description
            </label>
            <textarea
              name="description"
              value={formData.description}
              onChange={handleChange}
              rows={3}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              placeholder="Optional description"
              disabled={isLoading}
            />
          </div>

          <div className="flex space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500 transition-colors"
              disabled={isLoading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex-1 px-4 py-2 bg-purple-600 hover:bg-purple-700 dark:bg-purple-700 dark:hover:bg-purple-800 text-white rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500 disabled:opacity-50 transition-colors"
              disabled={isLoading}
            >
              {isLoading ? 'Saving...' : budget ? 'Update' : 'Create'} Budget
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default BudgetForm;
