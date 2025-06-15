import React, { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { MagnifyingGlassIcon, MoonIcon, SunIcon } from '@heroicons/react/24/outline';
import Logo from './components/ui/Logo';
import toast, { Toaster } from 'react-hot-toast';
import { useTheme } from './context/ThemeContext';
import { useAuth } from './context/AuthContext';
import ExpenseForm from './components/forms/ExpenseForm';
import IncomeForm from './components/forms/IncomeForm';
import BudgetForm from './components/forms/BudgetForm';
import ConfirmDialog from './components/ui/ConfirmDialog';
import CurrencyDisplay from './components/ui/CurrencyDisplay';
import SearchAndFilter from './components/ui/SearchAndFilter';
import { DashboardSkeleton, BudgetsGridSkeleton } from './components/ui/DashboardSkeleton';
import { EnhancedExpensesTableSkeleton, EnhancedIncomeTableSkeleton } from './components/ui/TableSkeleton';
import { expenseService } from './services/expenseService';
import { incomeService } from './services/incomeService';
import { budgetService } from './services/budgetService';
import { authService } from './services/authService';
import { filterTransactions, getUniqueCategories } from './utils/filterUtils';
import Profile from './pages/Profile';
import Analytics from './pages/Analytics';
import Dashboard from './pages/Dashboard';
import SupportMe from './pages/SupportMe';
import ErrorBoundary from './components/ErrorBoundary';
import BudgetCard from './components/ui/BudgetCard';
import UniversalSearch from './components/ui/UniversalSearch';
import { searchService } from './services/searchService';

// Navigation Component
const Navbar = ({ onProfileClick, onMenuClick, onSearchOpen }) => {
  const { theme, toggleTheme } = useTheme();
  const { user } = useAuth();

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-white/95 dark:bg-gray-800/95 backdrop-blur-sm shadow-sm border-b border-gray-200 dark:border-gray-700">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex items-center">
            {/* Mobile menu button */}
            <button
              onClick={onMenuClick}
              className="text-gray-500 hover:text-gray-600 dark:text-gray-400 dark:hover:text-gray-300 lg:hidden mr-4 p-2 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700"
              aria-label="Open sidebar"
            >
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
            <Link to="/dashboard" className="flex items-center space-x-2">
              <Logo size="md" useCustomIcon={true} showText={false} />
              <h1 className="text-xl font-bold text-gray-900 dark:text-white">Finlogy</h1>
            </Link>
          </div>

          {/* Center - Universal Search Bar (Circular & Extra Large) */}
          <div className="hidden md:flex flex-1 justify-center items-center max-w-3xl mx-12">
            <button
              onClick={onSearchOpen}
              className="flex items-center space-x-5 px-8 py-4 bg-gray-50 dark:bg-gray-700/50 rounded-full border border-gray-200 dark:border-gray-600 text-left hover:bg-white dark:hover:bg-gray-700 hover:border-blue-300 dark:hover:border-blue-500 hover:shadow-xl transition-all duration-200 interactive-card group min-w-0"
              style={{
                transform: 'scale(1)',
                transition: 'all 200ms ease-in-out',
                width: 'min(650px, calc(100vw - 250px))',
                height: '52px'
              }}
              onMouseEnter={(e) => {
                e.target.style.transform = 'scale(1.02)';
                e.target.style.boxShadow = '0 4px 12px rgba(59, 130, 246, 0.15), 0 0 0 1px rgba(59, 130, 246, 0.2)';
              }}
              onMouseLeave={(e) => {
                e.target.style.transform = 'scale(1)';
                e.target.style.boxShadow = '';
              }}
            >
              <MagnifyingGlassIcon className="h-5 w-5 text-gray-400 dark:text-gray-500 group-hover:text-blue-500 dark:group-hover:text-blue-400 transition-colors flex-shrink-0" />
              <span className="text-gray-500 dark:text-gray-400 flex-1 text-sm font-medium group-hover:text-gray-700 dark:group-hover:text-gray-300 transition-colors truncate">
                Search expenses, income, budgets...
              </span>
              <kbd className="px-1.5 py-0.5 bg-gray-200 dark:bg-gray-600 text-gray-500 dark:text-gray-400 rounded text-xs font-medium border border-gray-300 dark:border-gray-500 group-hover:bg-blue-100 dark:group-hover:bg-blue-900/30 group-hover:text-blue-600 dark:group-hover:text-blue-400 group-hover:border-blue-300 dark:group-hover:border-blue-500 transition-all flex-shrink-0">
                /
              </kbd>
            </button>
          </div>

          <div className="flex items-center space-x-2">
            {/* Mobile search button */}
            <button
              onClick={onSearchOpen}
              className="md:hidden p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 transition-all duration-200 interactive-card"
              title="Search (Ctrl+K)"
              style={{
                transform: 'scale(1)',
                transition: 'all 200ms ease-in-out'
              }}
              onMouseEnter={(e) => {
                e.target.style.transform = 'scale(1.02)';
                e.target.style.boxShadow = '0 2px 8px rgba(59, 130, 246, 0.15)';
              }}
              onMouseLeave={(e) => {
                e.target.style.transform = 'scale(1)';
                e.target.style.boxShadow = '';
              }}
            >
              <MagnifyingGlassIcon className="h-5 w-5 text-gray-500 dark:text-gray-400 hover:text-blue-500 dark:hover:text-blue-400 transition-colors" />
            </button>
            {/* Theme toggle */}
            <button
              onClick={toggleTheme}
              className="p-2 text-gray-500 hover:text-gray-600 dark:text-gray-400 dark:hover:text-gray-300 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
              title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            >
              {theme === 'dark' ? (
                <SunIcon className="h-5 w-5" />
              ) : (
                <MoonIcon className="h-5 w-5" />
              )}
            </button>

            {/* Profile button */}
            <button
              onClick={onProfileClick}
              className="flex items-center space-x-2 p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              title={`Profile - ${user?.name || 'User'}`}
            >
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-blue-700 rounded-full flex items-center justify-center text-white font-medium text-sm shadow-md hover:shadow-lg transition-shadow">
                {user?.name ? user.name.charAt(0).toUpperCase() : 'U'}
              </div>
              <span className="hidden sm:block text-gray-700 dark:text-gray-300 font-medium">{user?.name || 'User'}</span>
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
};

// Sidebar Component
const Sidebar = ({ currentPage, onPageChange, isOpen, onClose }) => {
  const pages = [
    { id: 'dashboard', name: 'Dashboard', icon: '📊' },
    { id: 'expenses', name: 'Expenses', icon: '💸' },
    { id: 'income', name: 'Income', icon: '💰' },
    { id: 'budgets', name: 'Budgets', icon: '🎯' },
    { id: 'analytics', name: 'Analytics', icon: '📈' },
    { id: 'profile', name: 'Profile', icon: '👤' },
    { id: 'support', name: 'Support Me', icon: '❤️' },
  ];

  return (
    <>
      {/* Mobile sidebar overlay */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-gray-600 bg-opacity-75 dark:bg-gray-900 dark:bg-opacity-75 lg:hidden z-30"
          onClick={onClose}
        />
      )}

      {/* Sidebar */}
      <div className={`
        fixed top-16 bottom-0 left-0 z-40 w-64 bg-gray-50 dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 shadow-lg sidebar-transition
        lg:translate-x-0 lg:static lg:inset-0 lg:z-auto lg:top-0 lg:shadow-none
        ${isOpen ? 'translate-x-0' : '-translate-x-full'}
      `}>
        {/* Navigation */}
        <div className="p-4 overflow-y-auto h-full custom-scrollbar">
          {/* Mobile close button - positioned at top of navigation */}
          <div className="flex items-center justify-between mb-4 lg:hidden">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Menu</h2>
            <button
              onClick={onClose}
              className="text-gray-500 hover:text-gray-600 dark:text-gray-400 dark:hover:text-gray-300 p-2 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700"
              aria-label="Close sidebar"
            >
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <nav className="space-y-2">
            {pages.map((page) => (
              <button
                key={page.id}
                onClick={() => onPageChange(page.id)}
                className={`w-full flex items-center px-3 py-2 text-left rounded-md transition-all duration-200 ease-in-out border border-transparent hover-glow-subtle ${
                  currentPage === page.id
                    ? 'bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 font-medium border-blue-200 dark:border-blue-700'
                    : 'text-gray-700 dark:text-gray-300'
                }`}
              >
                <span className="mr-3">{page.icon}</span>
                {page.name}
              </button>
            ))}
          </nav>
        </div>
      </div>
    </>
  );
};

// Note: Login and Register components are now in separate files



// Expenses Component with full CRUD functionality
const Expenses = () => {
  const [expenses, setExpenses] = useState([]);
  const [filteredExpenses, setFilteredExpenses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showExpenseForm, setShowExpenseForm] = useState(false);
  const [editingExpense, setEditingExpense] = useState(null);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [deletingExpense, setDeletingExpense] = useState(null);
  const [formLoading, setFormLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({});

  // Fetch expenses from API
  const fetchExpenses = async () => {
    try {
      setLoading(true);
      const response = await expenseService.getExpenses();
      const expenseData = response.data || [];
      setExpenses(expenseData);
      setFilteredExpenses(expenseData);
    } catch (error) {
      console.error('Error fetching expenses:', error);
      toast.error('Failed to load expenses');
      setExpenses([]);
      setFilteredExpenses([]);
    } finally {
      setLoading(false);
    }
  };

  // Apply search and filters
  const applyFilters = () => {
    const filtered = filterTransactions(expenses, searchTerm, filters);
    setFilteredExpenses(filtered);
  };

  // Handle search
  const handleSearch = (term) => {
    setSearchTerm(term);
  };

  // Handle filters
  const handleFilter = (newFilters) => {
    setFilters(newFilters);
  };

  // Apply filters when search term or filters change
  useEffect(() => {
    applyFilters();
  }, [searchTerm, filters, expenses]);

  useEffect(() => {
    fetchExpenses();
  }, []);

  const handleAddExpense = async (expenseData) => {
    try {
      setFormLoading(true);
      await expenseService.createExpense(expenseData);
      toast.success('Expense added successfully!');
      setShowExpenseForm(false);
      fetchExpenses(); // Refresh the list to show the new expense
    } catch (error) {
      console.error('Error adding expense:', error);
      toast.error('Failed to add expense');
    } finally {
      setFormLoading(false);
    }
  };

  const handleEditExpense = async (expenseData) => {
    try {
      setFormLoading(true);
      await expenseService.updateExpense(editingExpense._id, expenseData);
      toast.success('Expense updated successfully!');
      setEditingExpense(null);
      fetchExpenses(); // Refresh the list to show the updated expense
    } catch (error) {
      console.error('Error updating expense:', error);
      toast.error('Failed to update expense');
    } finally {
      setFormLoading(false);
    }
  };

  const handleDeleteExpense = async () => {
    try {
      setFormLoading(true);
      await expenseService.deleteExpense(deletingExpense._id);
      toast.success('Expense deleted successfully!');
      setShowDeleteDialog(false);
      setDeletingExpense(null);
      fetchExpenses(); // Refresh the list to remove the deleted expense
    } catch (error) {
      console.error('Error deleting expense:', error);
      toast.error('Failed to delete expense');
    } finally {
      setFormLoading(false);
    }
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays === 1) return 'Today';
    if (diffDays === 2) return 'Yesterday';
    if (diffDays <= 7) return `${diffDays - 1} days ago`;
    return date.toLocaleDateString();
  };

  return (
    <div className="p-4 sm:p-6 lg:p-8">
      {/* Mobile-optimized header */}
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4 mb-6 sm:mb-8">
        <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">Expenses</h1>
        <button
          onClick={() => setShowExpenseForm(true)}
          className="bg-blue-600 hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-800 text-white px-4 py-3 sm:py-2 rounded-lg sm:rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors font-medium text-sm sm:text-base min-h-[44px] sm:min-h-auto"
        >
          <span className="sm:hidden">+ Add New Expense</span>
          <span className="hidden sm:inline">+ Add Expense</span>
        </button>
      </div>

      {/* Search and Filter */}
      <SearchAndFilter
        onSearch={handleSearch}
        onFilter={handleFilter}
        categories={getUniqueCategories(expenses, 'category')}
        placeholder="Search expenses by title, description, or category..."
        resultCount={filteredExpenses.length}
        totalCount={expenses.length}
        isLoading={loading}
        suggestions={expenses.map(expense => expense.title).filter((title, index, array) => array.indexOf(title) === index)}
        onSuggestionSelect={(suggestion) => {
          // Auto-focus on the selected expense if needed
          console.log('Selected suggestion:', suggestion);
        }}
        persistFilters={true}
        filterKey="expenses"
      />

      {loading ? (
        <EnhancedExpensesTableSkeleton rows={8} />
      ) : (
        /* Responsive layout: Table on desktop, Cards on mobile */
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 overflow-hidden">
          {expenses.length === 0 ? (
            <div className="p-6 sm:p-8 text-center">
              <p className="text-gray-500 dark:text-gray-400">No expenses found. Add your first expense to get started!</p>
            </div>
          ) : filteredExpenses.length === 0 ? (
            <div className="p-6 sm:p-8 text-center">
              <div className="text-gray-400 dark:text-gray-500 mb-4">
                <MagnifyingGlassIcon className="h-12 w-12 mx-auto" />
              </div>
              <p className="text-gray-500 dark:text-gray-400 text-lg font-medium mb-2">No results found</p>
              <p className="text-gray-400 dark:text-gray-500">Try adjusting your search or filter criteria</p>
            </div>
          ) : (
            <>
              {/* Desktop Table View */}
              <div className="hidden lg:block">
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead className="bg-gray-50 dark:bg-gray-700">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Description</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Category</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Amount</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Date</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                    {filteredExpenses.map((expense) => (
                      <tr key={expense._id} className="hover-glow cursor-pointer transition-all duration-200 ease-in-out border border-transparent">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div>
                            <div className="text-sm font-medium text-gray-900 dark:text-white">{expense.title}</div>
                            {expense.description && (
                              <div className="text-sm text-gray-500 dark:text-gray-400">{expense.description}</div>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300">
                            {expense.category.charAt(0).toUpperCase() + expense.category.slice(1)}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                          <CurrencyDisplay amount={expense.amount} size="sm" />
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                          {formatDate(expense.date)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <button
                            onClick={() => setEditingExpense(expense)}
                            className="text-blue-600 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 mr-3"
                          >
                            Edit
                          </button>
                          <button
                            onClick={() => {
                              setDeletingExpense(expense);
                              setShowDeleteDialog(true);
                            }}
                            className="text-red-600 dark:text-red-400 hover:text-red-900 dark:hover:text-red-300"
                          >
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Mobile Card View */}
              <div className="lg:hidden divide-y divide-gray-200 dark:divide-gray-700">
                {filteredExpenses.map((expense) => (
                  <div key={expense._id} className="p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                    <div className="flex justify-between items-start mb-3">
                      <div className="flex-1 min-w-0">
                        <h3 className="text-base font-medium text-gray-900 dark:text-white truncate">{expense.title}</h3>
                        {expense.description && (
                          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1 line-clamp-2">{expense.description}</p>
                        )}
                      </div>
                      <div className="ml-4 flex-shrink-0">
                        <CurrencyDisplay amount={expense.amount} size="base" className="font-semibold" />
                      </div>
                    </div>

                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300">
                          {expense.category.charAt(0).toUpperCase() + expense.category.slice(1)}
                        </span>
                        <span className="text-sm text-gray-500 dark:text-gray-400">
                          {formatDate(expense.date)}
                        </span>
                      </div>

                      <div className="flex items-center space-x-1">
                        <button
                          onClick={() => setEditingExpense(expense)}
                          className="p-2 text-blue-600 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-md transition-colors min-h-[44px] min-w-[44px] flex items-center justify-center"
                          aria-label="Edit expense"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                          </svg>
                        </button>
                        <button
                          onClick={() => {
                            setDeletingExpense(expense);
                            setShowDeleteDialog(true);
                          }}
                          className="p-2 text-red-600 dark:text-red-400 hover:text-red-900 dark:hover:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-md transition-colors min-h-[44px] min-w-[44px] flex items-center justify-center"
                          aria-label="Delete expense"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}

      {/* Add/Edit Expense Form */}
      {(showExpenseForm || editingExpense) && (
        <ExpenseForm
          isOpen={showExpenseForm || !!editingExpense}
          onClose={() => {
            setShowExpenseForm(false);
            setEditingExpense(null);
          }}
          onSubmit={editingExpense ? handleEditExpense : handleAddExpense}
          expense={editingExpense}
          isLoading={formLoading}
        />
      )}

      {/* Delete Confirmation Dialog */}
      {showDeleteDialog && (
        <ConfirmDialog
          isOpen={showDeleteDialog}
          onClose={() => {
            setShowDeleteDialog(false);
            setDeletingExpense(null);
          }}
          onConfirm={handleDeleteExpense}
          title="Delete Expense"
          message={`Are you sure you want to delete "${deletingExpense?.title}"? This action cannot be undone.`}
          confirmText="Delete"
          type="danger"
          isLoading={formLoading}
        />
      )}
    </div>
  );
};

// Income Component with full CRUD functionality
const Income = () => {
  const [incomeList, setIncomeList] = useState([]);
  const [filteredIncomeList, setFilteredIncomeList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showIncomeForm, setShowIncomeForm] = useState(false);
  const [editingIncome, setEditingIncome] = useState(null);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [deletingIncome, setDeletingIncome] = useState(null);
  const [formLoading, setFormLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({});

  // Fetch income from API
  const fetchIncome = async () => {
    try {
      setLoading(true);
      const response = await incomeService.getIncome();
      const incomeData = response.data || [];
      setIncomeList(incomeData);
      setFilteredIncomeList(incomeData);
    } catch (error) {
      console.error('Error fetching income:', error);
      toast.error('Failed to load income');
      setIncomeList([]);
      setFilteredIncomeList([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncome();
  }, []);

  // Apply search and filters for income
  const applyIncomeFilters = () => {
    const filtered = filterTransactions(incomeList, searchTerm, filters);
    setFilteredIncomeList(filtered);
  };

  // Handle search for income
  const handleIncomeSearch = (term) => {
    setSearchTerm(term);
  };

  // Handle filters for income
  const handleIncomeFilter = (newFilters) => {
    setFilters(newFilters);
  };

  // Apply filters when search term or filters change
  useEffect(() => {
    applyIncomeFilters();
  }, [searchTerm, filters, incomeList]);

  const handleAddIncome = async (incomeData) => {
    try {
      setFormLoading(true);
      await incomeService.createIncome(incomeData);
      toast.success('Income added successfully!');
      setShowIncomeForm(false);
      fetchIncome(); // Refresh the list to show the new income
    } catch (error) {
      console.error('Error adding income:', error);
      toast.error('Failed to add income');
    } finally {
      setFormLoading(false);
    }
  };

  const handleEditIncome = async (incomeData) => {
    try {
      setFormLoading(true);
      await incomeService.updateIncome(editingIncome._id, incomeData);
      toast.success('Income updated successfully!');
      setEditingIncome(null);
      fetchIncome(); // Refresh the list to show the updated income
    } catch (error) {
      console.error('Error updating income:', error);
      toast.error('Failed to update income');
    } finally {
      setFormLoading(false);
    }
  };

  const handleDeleteIncome = async () => {
    try {
      setFormLoading(true);
      await incomeService.deleteIncome(deletingIncome._id);
      toast.success('Income deleted successfully!');
      setShowDeleteDialog(false);
      setDeletingIncome(null);
      fetchIncome(); // Refresh the list to remove the deleted income
    } catch (error) {
      console.error('Error deleting income:', error);
      toast.error('Failed to delete income');
    } finally {
      setFormLoading(false);
    }
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays === 1) return 'Today';
    if (diffDays === 2) return 'Yesterday';
    if (diffDays <= 7) return `${diffDays - 1} days ago`;
    return date.toLocaleDateString();
  };

  return (
    <div className="p-4 sm:p-6 lg:p-8">
      {/* Mobile-optimized header */}
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4 mb-6 sm:mb-8">
        <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">Income</h1>
        <button
          onClick={() => setShowIncomeForm(true)}
          className="bg-green-600 hover:bg-green-700 dark:bg-green-700 dark:hover:bg-green-800 text-white px-4 py-3 sm:py-2 rounded-lg sm:rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 transition-colors font-medium text-sm sm:text-base min-h-[44px] sm:min-h-auto"
        >
          <span className="sm:hidden">+ Add New Income</span>
          <span className="hidden sm:inline">+ Add Income</span>
        </button>
      </div>

      {/* Search and Filter */}
      <SearchAndFilter
        onSearch={handleIncomeSearch}
        onFilter={handleIncomeFilter}
        categories={getUniqueCategories(incomeList, 'source')}
        placeholder="Search income by title, description, or source..."
        resultCount={filteredIncomeList.length}
        totalCount={incomeList.length}
        isLoading={loading}
        suggestions={incomeList.map(income => income.title).filter((title, index, array) => array.indexOf(title) === index)}
        onSuggestionSelect={(suggestion) => {
          // Auto-focus on the selected income if needed
          console.log('Selected suggestion:', suggestion);
        }}
        persistFilters={true}
        filterKey="income"
      />

      {loading ? (
        <EnhancedIncomeTableSkeleton rows={8} />
      ) : (
        /* Responsive layout: Table on desktop, Cards on mobile */
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 overflow-hidden">
          {incomeList.length === 0 ? (
            <div className="p-6 sm:p-8 text-center">
              <p className="text-gray-500 dark:text-gray-400">No income entries found. Add your first income to get started!</p>
            </div>
          ) : filteredIncomeList.length === 0 ? (
            <div className="p-6 sm:p-8 text-center">
              <div className="text-gray-400 dark:text-gray-500 mb-4">
                <MagnifyingGlassIcon className="h-12 w-12 mx-auto" />
              </div>
              <p className="text-gray-500 dark:text-gray-400 text-lg font-medium mb-2">No results found</p>
              <p className="text-gray-400 dark:text-gray-500">Try adjusting your search or filter criteria</p>
            </div>
          ) : (
            <>
              {/* Desktop Table View */}
              <div className="hidden lg:block">
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead className="bg-gray-50 dark:bg-gray-700">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Description</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Source</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Amount</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Date</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                    {filteredIncomeList.map((income) => (
                      <tr key={income._id} className="hover-glow cursor-pointer transition-all duration-200 ease-in-out border border-transparent">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div>
                            <div className="text-sm font-medium text-gray-900 dark:text-white">{income.title}</div>
                            {income.description && (
                              <div className="text-sm text-gray-500 dark:text-gray-400">{income.description}</div>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/50 text-green-800 dark:text-green-300">
                            {income.source.charAt(0).toUpperCase() + income.source.slice(1)}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-green-600 dark:text-green-400">
                          <CurrencyDisplay amount={income.amount} variant="success" size="sm" />
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                          {formatDate(income.date)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <button
                            onClick={() => setEditingIncome(income)}
                            className="text-blue-600 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 mr-3"
                          >
                            Edit
                          </button>
                          <button
                            onClick={() => {
                              setDeletingIncome(income);
                              setShowDeleteDialog(true);
                            }}
                            className="text-red-600 dark:text-red-400 hover:text-red-900 dark:hover:text-red-300"
                          >
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Mobile Card View */}
              <div className="lg:hidden divide-y divide-gray-200 dark:divide-gray-700">
                {filteredIncomeList.map((income) => (
                  <div key={income._id} className="p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                    <div className="flex justify-between items-start mb-3">
                      <div className="flex-1 min-w-0">
                        <h3 className="text-base font-medium text-gray-900 dark:text-white truncate">{income.title}</h3>
                        {income.description && (
                          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1 line-clamp-2">{income.description}</p>
                        )}
                      </div>
                      <div className="ml-4 flex-shrink-0">
                        <CurrencyDisplay amount={income.amount} variant="success" size="base" className="font-semibold" />
                      </div>
                    </div>

                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/50 text-green-800 dark:text-green-300">
                          {income.source.charAt(0).toUpperCase() + income.source.slice(1)}
                        </span>
                        <span className="text-sm text-gray-500 dark:text-gray-400">
                          {formatDate(income.date)}
                        </span>
                      </div>

                      <div className="flex items-center space-x-1">
                        <button
                          onClick={() => setEditingIncome(income)}
                          className="p-2 text-blue-600 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-md transition-colors min-h-[44px] min-w-[44px] flex items-center justify-center"
                          aria-label="Edit income"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                          </svg>
                        </button>
                        <button
                          onClick={() => {
                            setDeletingIncome(income);
                            setShowDeleteDialog(true);
                          }}
                          className="p-2 text-red-600 dark:text-red-400 hover:text-red-900 dark:hover:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-md transition-colors min-h-[44px] min-w-[44px] flex items-center justify-center"
                          aria-label="Delete income"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}

      {/* Add/Edit Income Form */}
      {(showIncomeForm || editingIncome) && (
        <IncomeForm
          isOpen={showIncomeForm || !!editingIncome}
          onClose={() => {
            setShowIncomeForm(false);
            setEditingIncome(null);
          }}
          onSubmit={editingIncome ? handleEditIncome : handleAddIncome}
          income={editingIncome}
          isLoading={formLoading}
        />
      )}

      {/* Delete Confirmation Dialog */}
      {showDeleteDialog && (
        <ConfirmDialog
          isOpen={showDeleteDialog}
          onClose={() => {
            setShowDeleteDialog(false);
            setDeletingIncome(null);
          }}
          onConfirm={handleDeleteIncome}
          title="Delete Income"
          message={`Are you sure you want to delete "${deletingIncome?.title}"? This action cannot be undone.`}
          confirmText="Delete"
          type="danger"
          isLoading={formLoading}
        />
      )}
    </div>
  );
};

// Budgets Component with full CRUD functionality
const Budgets = () => {
  const [budgets, setBudgets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showBudgetForm, setShowBudgetForm] = useState(false);
  const [editingBudget, setEditingBudget] = useState(null);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [deletingBudget, setDeletingBudget] = useState(null);
  const [formLoading, setFormLoading] = useState(false);

  // Fetch budgets from API
  const fetchBudgets = async () => {
    try {
      setLoading(true);
      const response = await budgetService.getBudgets();
      setBudgets(response.data || []);
    } catch (error) {
      console.error('Error fetching budgets:', error);
      toast.error('Failed to load budgets');
      setBudgets([]); // Set empty array on error instead of demo data
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBudgets();
  }, []);

  const handleAddBudget = async (budgetData) => {
    try {
      setFormLoading(true);
      await budgetService.createBudget(budgetData);
      toast.success('Budget created successfully!');
      setShowBudgetForm(false);
      fetchBudgets(); // Refresh the list to show the new budget
    } catch (error) {
      console.error('Error adding budget:', error);
      toast.error('Failed to create budget');
    } finally {
      setFormLoading(false);
    }
  };

  const handleEditBudget = async (budgetData) => {
    try {
      setFormLoading(true);
      await budgetService.updateBudget(editingBudget._id, budgetData);
      toast.success('Budget updated successfully!');
      setEditingBudget(null);
      fetchBudgets(); // Refresh the list to show the updated budget
    } catch (error) {
      console.error('Error updating budget:', error);
      toast.error('Failed to update budget');
    } finally {
      setFormLoading(false);
    }
  };

  const handleDeleteBudget = async () => {
    try {
      setFormLoading(true);
      await budgetService.deleteBudget(deletingBudget._id);
      toast.success('Budget deleted successfully!');
      setShowDeleteDialog(false);
      setDeletingBudget(null);
      fetchBudgets(); // Refresh the list to remove the deleted budget
    } catch (error) {
      console.error('Error deleting budget:', error);
      toast.error('Failed to delete budget');
    } finally {
      setFormLoading(false);
    }
  };

  const getBudgetStatus = (budget) => {
    const percentage = (budget.spent / budget.amount) * 100;
    if (percentage >= 100) return { status: 'exceeded', color: 'red' };
    if (percentage >= (budget.alertThreshold || 80)) return { status: 'warning', color: 'yellow' };
    return { status: 'on-track', color: 'green' };
  };

  const getProgressBarColor = (status) => {
    switch (status) {
      case 'exceeded': return 'bg-red-500';
      case 'warning': return 'bg-yellow-500';
      default: return 'bg-green-500';
    }
  };

  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Budgets</h1>
        <button
          onClick={() => setShowBudgetForm(true)}
          className="bg-purple-600 hover:bg-purple-700 dark:bg-purple-700 dark:hover:bg-purple-800 text-white px-4 py-2 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500 btn-interactive"
        >
          + Create Budget
        </button>
      </div>

      {loading ? (
        <BudgetsGridSkeleton items={6} />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {budgets.length === 0 ? (
            <div className="col-span-full bg-white dark:bg-gray-800 p-8 rounded-lg shadow border border-gray-200 dark:border-gray-700 text-center">
              <p className="text-gray-500 dark:text-gray-400">No budgets found. Create your first budget to get started!</p>
            </div>
          ) : (
            budgets.map((budget, index) => (
              <div
                key={budget._id}
                style={{ animationDelay: `${index * 100}ms` }}
                className="animate-slide-in-up"
              >
                <BudgetCard
                  budget={budget}
                  onEdit={setEditingBudget}
                  onDelete={(budgetId) => {
                    setDeletingBudget(budgets.find(b => b._id === budgetId));
                    setShowDeleteDialog(true);
                  }}
                  CurrencyDisplay={CurrencyDisplay}
                  getBudgetStatus={getBudgetStatus}
                  getProgressBarColor={getProgressBarColor}
                />
              </div>
            ))
          )}
        </div>
      )}

      {/* Add/Edit Budget Form */}
      {(showBudgetForm || editingBudget) && (
        <BudgetForm
          isOpen={showBudgetForm || !!editingBudget}
          onClose={() => {
            setShowBudgetForm(false);
            setEditingBudget(null);
          }}
          onSubmit={editingBudget ? handleEditBudget : handleAddBudget}
          budget={editingBudget}
          isLoading={formLoading}
        />
      )}

      {/* Delete Confirmation Dialog */}
      {showDeleteDialog && (
        <ConfirmDialog
          isOpen={showDeleteDialog}
          onClose={() => {
            setShowDeleteDialog(false);
            setDeletingBudget(null);
          }}
          onConfirm={handleDeleteBudget}
          title="Delete Budget"
          message={`Are you sure you want to delete "${deletingBudget?.name}"? This action cannot be undone.`}
          confirmText="Delete"
          type="danger"
          isLoading={formLoading}
        />
      )}
    </div>
  );
};



function AppContent() {
  const location = useLocation();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchData, setSearchData] = useState({
    expenses: [],
    income: [],
    budgets: [],
    categories: []
  });

  // Get current page from route
  const getCurrentPage = () => {
    const path = location.pathname;
    console.log('Current path:', path); // Debug log
    if (path.includes('/expenses')) return 'expenses';
    if (path.includes('/income')) return 'income';
    if (path.includes('/budgets')) return 'budgets';
    if (path.includes('/analytics')) return 'analytics';
    if (path.includes('/profile')) return 'profile';
    if (path.includes('/support-me')) return 'support';
    return 'dashboard';
  };

  const currentPage = getCurrentPage();

  // Global keyboard shortcut for search (Ctrl+K / Cmd+K)
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Check for Ctrl+K (Windows/Linux) or Cmd+K (Mac)
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        handleSearchOpen();
      }
      // Also support "/" key for quick search
      if (e.key === '/' && !searchOpen && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
        e.preventDefault();
        handleSearchOpen();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [searchOpen]);

  // Load search data when component mounts
  useEffect(() => {
    loadSearchData();
  }, []);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Ctrl+K or Cmd+K to open search
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setSearchOpen(true);
      }
      // Escape to close search
      if (e.key === 'Escape' && searchOpen) {
        setSearchOpen(false);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [searchOpen]);

  const loadSearchData = async () => {
    try {
      const data = await searchService.getAllSearchData();
      setSearchData(data);
    } catch (error) {
      console.error('Error loading search data:', error);
    }
  };

  const handleProfileClick = () => {
    navigate('/profile');
    // Close mobile sidebar if open
    setSidebarOpen(false);
  };

  const handlePageChange = (page) => {
    // Handle special routing cases
    const route = page === 'support' ? '/support-me' : `/${page}`;
    console.log('Navigation: page =', page, ', route =', route); // Debug log
    navigate(route);
    // Close mobile sidebar if open
    setSidebarOpen(false);
    // Scroll to top of main content
    const mainContent = document.querySelector('main');
    if (mainContent) {
      mainContent.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const handleSearchOpen = () => {
    setSearchOpen(true);
  };

  const handleSearchClose = () => {
    setSearchOpen(false);
  };

  const handleSearch = (query, filters) => {
    // Implement search functionality
    console.log('Search:', query, filters);
    // You can add more sophisticated search logic here
  };

  const handleSearchNavigate = (route) => {
    // Navigate to the appropriate page and potentially highlight the item
    navigate(route);
    setSidebarOpen(false);
    setSearchOpen(false);

    // Scroll to top
    setTimeout(() => {
      const mainContent = document.querySelector('main');
      if (mainContent) {
        mainContent.scrollTo({ top: 0, behavior: 'smooth' });
      }
    }, 100);
  };

  const renderPage = () => {
    console.log('Rendering page for currentPage:', currentPage); // Debug log
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard onNavigate={handlePageChange} />;
      case 'expenses':
        return <Expenses />;
      case 'income':
        return <Income />;
      case 'budgets':
        return <Budgets />;
      case 'analytics':
        return (
          <ErrorBoundary>
            <Analytics />
          </ErrorBoundary>
        );
      case 'profile':
        return <Profile />;
      case 'support':
        return <SupportMe />;
      default:
        return <Dashboard onNavigate={handlePageChange} />;
    }
  };

  // Get user from AuthContext
  const { user } = useAuth();

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <Toaster
        position="top-right"
        toastOptions={{
          className: 'dark:bg-gray-800 dark:text-white',
          style: {
            background: 'var(--toast-bg)',
            color: 'var(--toast-color)',
          },
        }}
      />
      <Navbar
        onProfileClick={handleProfileClick}
        onMenuClick={() => setSidebarOpen(true)}
        onSearchOpen={handleSearchOpen}
      />

      {/* Universal Search */}
      <UniversalSearch
        isOpen={searchOpen}
        onClose={handleSearchClose}
        onSearch={handleSearch}
        onNavigate={handleSearchNavigate}
        data={searchData}
      />
      <div className="flex h-screen pt-16"> {/* pt-16 to account for fixed navbar */}
        <Sidebar
          currentPage={currentPage}
          onPageChange={handlePageChange}
          isOpen={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
        />
        <div className="flex-1 overflow-hidden lg:ml-0"> {/* Ensure proper spacing on desktop */}
          <main className="h-full overflow-y-auto bg-gray-50 dark:bg-gray-900 custom-scrollbar scroll-smooth">
            <div className="max-w-full">
              {renderPage()}
            </div>
          </main>
        </div>
      </div>
    </div>
  );
}

// Export AppContent as the main App component
export default function App() {
  return <AppContent />;
}


