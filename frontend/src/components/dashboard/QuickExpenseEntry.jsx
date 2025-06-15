import React, { useState, useEffect } from 'react';
import { PlusIcon, CurrencyDollarIcon, SparklesIcon } from '@heroicons/react/24/outline';
import { useCurrency } from '../../context/CurrencyContext';
import { useTheme } from '../../context/ThemeContext';
import { aiService } from '../../services/aiService';
import { CategoryBadge } from '../ui/CategoryIcon';
import { getAllCategories } from '../../utils/categoryConfig';
import toast from 'react-hot-toast';

const QuickExpenseEntry = ({ onExpenseAdded, commonCategories = [] }) => {
  const { formatAmount } = useCurrency();
  const { isDark } = useTheme();
  const [isExpanded, setIsExpanded] = useState(false);
  const [formData, setFormData] = useState({
    title: '',
    amount: '',
    category: ''
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isCategorizingAI, setIsCategorizingAI] = useState(false);
  const [aiSuggestion, setAiSuggestion] = useState(null);

  // Get categories from centralized config
  const allCategories = getAllCategories();
  const defaultCategories = [
    'food', 'transportation', 'utilities', 'entertainment',
    'healthcare', 'shopping', 'education', 'other'
  ];

  const categories = commonCategories.length > 0 ? commonCategories : defaultCategories;

  // AI auto-categorization when title changes
  useEffect(() => {
    const autoCategorizeTitleWithAI = async () => {
      if (formData.title.length >= 3 && formData.amount && !formData.category) {
        setIsCategorizingAI(true);
        try {
          const suggestedCategory = await aiService.categorizeTransaction(
            formData.title,
            parseFloat(formData.amount) || 0
          );

          // Map AI category to our available categories
          const mappedCategory = mapAiCategoryToLocal(suggestedCategory);
          if (mappedCategory) {
            setFormData(prev => ({ ...prev, category: mappedCategory }));
            setAiSuggestion(suggestedCategory);
            toast.success(`AI suggested: ${suggestedCategory}`, { duration: 2000 });
          }
        } catch (error) {
          console.warn('AI categorization failed:', error);
        } finally {
          setIsCategorizingAI(false);
        }
      }
    };

    const timeoutId = setTimeout(autoCategorizeTitleWithAI, 1000); // Debounce
    return () => clearTimeout(timeoutId);
  }, [formData.title, formData.amount, formData.category]);

  // Map AI categories to local categories using centralized config
  const mapAiCategoryToLocal = (aiCategory) => {
    const categoryMap = {
      'Food & Dining': 'food',
      'Transportation': 'transportation',
      'Bills & Utilities': 'utilities',
      'Entertainment': 'entertainment',
      'Healthcare': 'healthcare',
      'Shopping': 'shopping',
      'Education': 'education',
      'Groceries': 'food',
      'Travel': 'travel',
      'Personal Care': 'personal',
      'Other': 'other'
    };

    const mapped = categoryMap[aiCategory] || aiCategory.toLowerCase();
    // Ensure the mapped category exists in our config
    return allCategories.find(cat => cat.key === mapped) ? mapped : 'other';
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!formData.title.trim() || !formData.amount || !formData.category) {
      toast.error('Please fill in all fields');
      return;
    }

    const amount = parseFloat(formData.amount);
    if (isNaN(amount) || amount <= 0) {
      toast.error('Please enter a valid amount');
      return;
    }

    try {
      setIsSubmitting(true);
      
      const expenseData = {
        title: formData.title.trim(),
        amount: amount,
        category: formData.category,
        date: new Date().toISOString(),
        description: `Quick entry: ${formData.title}`
      };

      // Call the parent's expense addition handler
      await onExpenseAdded(expenseData);
      
      // Reset form
      setFormData({ title: '', amount: '', category: '' });
      setIsExpanded(false);
      
      toast.success(`Added ${formatAmount(amount, { showSymbol: true })} expense`);
    } catch (error) {
      console.error('Error adding quick expense:', error);
      toast.error('Failed to add expense');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancel = () => {
    setFormData({ title: '', amount: '', category: '' });
    setIsExpanded(false);
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700">
      {!isExpanded ? (
        // Collapsed state - Quick add button
        <button
          onClick={() => setIsExpanded(true)}
          className="w-full p-6 text-left hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors rounded-lg"
        >
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-blue-100 dark:bg-blue-900/50 rounded-lg">
              <PlusIcon className="h-5 w-5 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                Quick Expense Entry
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Add an expense quickly
              </p>
            </div>
          </div>
        </button>
      ) : (
        // Expanded state - Form
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-blue-100 dark:bg-blue-900/50 rounded-lg">
                <CurrencyDollarIcon className="h-5 w-5 text-blue-600 dark:text-blue-400" />
              </div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                Add Quick Expense
              </h3>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Title */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Description
              </label>
              <input
                type="text"
                value={formData.title}
                onChange={(e) => setFormData(prev => ({ ...prev, title: e.target.value }))}
                placeholder="e.g., Coffee, Lunch, Gas"
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                disabled={isSubmitting}
                autoFocus
              />
            </div>

            {/* Amount and Category Row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Amount */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Amount
                </label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-500 dark:text-gray-400">
                    ₹
                  </span>
                  <input
                    type="number"
                    value={formData.amount}
                    onChange={(e) => setFormData(prev => ({ ...prev, amount: e.target.value }))}
                    placeholder="0.00"
                    min="0"
                    step="0.01"
                    className="w-full pl-8 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                    disabled={isSubmitting}
                  />
                </div>
              </div>

              {/* Category */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Category
                  {isCategorizingAI && (
                    <span className="ml-2 inline-flex items-center text-xs text-blue-600 dark:text-blue-400">
                      <SparklesIcon className="h-3 w-3 mr-1 animate-pulse" />
                      AI suggesting...
                    </span>
                  )}
                  {aiSuggestion && formData.category && (
                    <span className="ml-2 inline-flex items-center text-xs text-green-600 dark:text-green-400">
                      <SparklesIcon className="h-3 w-3 mr-1" />
                      AI suggested
                    </span>
                  )}
                </label>
                <select
                  value={formData.category}
                  onChange={(e) => {
                    setFormData(prev => ({ ...prev, category: e.target.value }));
                    setAiSuggestion(null); // Clear AI suggestion when manually changed
                  }}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                  disabled={isSubmitting || isCategorizingAI}
                >
                  <option value="">
                    {isCategorizingAI ? 'AI is suggesting...' : 'Select category'}
                  </option>
                  {categories.map(category => {
                    const categoryConfig = allCategories.find(cat => cat.key === category);
                    return (
                      <option key={category} value={category}>
                        {categoryConfig ? categoryConfig.name : category.charAt(0).toUpperCase() + category.slice(1)}
                      </option>
                    );
                  })}
                </select>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex space-x-3 pt-2">
              <button
                type="submit"
                disabled={isSubmitting || !formData.title.trim() || !formData.amount || !formData.category}
                className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white py-2 px-4 rounded-lg font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 dark:focus:ring-offset-gray-800 btn-glow"
              >
                {isSubmitting ? 'Adding...' : 'Add Expense'}
              </button>
              <button
                type="button"
                onClick={handleCancel}
                disabled={isSubmitting}
                className="px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 dark:focus:ring-offset-gray-800"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};

export default QuickExpenseEntry;
