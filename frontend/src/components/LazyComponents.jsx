import React, { lazy, Suspense } from 'react';
import DashboardSkeleton from './skeletons/DashboardSkeleton';
import { EnhancedExpenseTableSkeleton, EnhancedIncomeTableSkeleton, BudgetsGridSkeleton } from './skeletons/TableSkeletons';

// Lazy load components for code splitting
const Dashboard = lazy(() => import('../pages/Dashboard'));
const Expenses = lazy(() => import('../pages/Expenses'));
const Income = lazy(() => import('../pages/Income'));
const Budgets = lazy(() => import('../pages/Budgets'));
const Analytics = lazy(() => import('../pages/Analytics'));
const Profile = lazy(() => import('../pages/Profile'));

// Optimized loading components with proper skeletons
const LoadingFallback = ({ type = 'dashboard' }) => {
  switch (type) {
    case 'expenses':
      return (
        <div className="p-8">
          <div className="flex justify-between items-center mb-8">
            <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-32 animate-pulse"></div>
            <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded w-32 animate-pulse"></div>
          </div>
          <EnhancedExpenseTableSkeleton rows={8} />
        </div>
      );
    case 'income':
      return (
        <div className="p-8">
          <div className="flex justify-between items-center mb-8">
            <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-24 animate-pulse"></div>
            <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded w-32 animate-pulse"></div>
          </div>
          <EnhancedIncomeTableSkeleton rows={8} />
        </div>
      );
    case 'budgets':
      return (
        <div className="p-8">
          <div className="flex justify-between items-center mb-8">
            <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-28 animate-pulse"></div>
            <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded w-36 animate-pulse"></div>
          </div>
          <BudgetsGridSkeleton items={6} />
        </div>
      );
    case 'analytics':
      return (
        <div className="p-8">
          <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-32 mb-8 animate-pulse"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow border border-gray-200 dark:border-gray-700">
                <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded w-3/4 mb-4 animate-pulse"></div>
                <div className="h-32 bg-gray-200 dark:bg-gray-700 rounded animate-pulse"></div>
              </div>
            ))}
          </div>
        </div>
      );
    case 'profile':
      return (
        <div className="p-8">
          <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-24 mb-8 animate-pulse"></div>
          <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow border border-gray-200 dark:border-gray-700">
            <div className="space-y-4">
              {[...Array(6)].map((_, i) => (
                <div key={i} className="flex items-center space-x-4">
                  <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-24 animate-pulse"></div>
                  <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded flex-1 animate-pulse"></div>
                </div>
              ))}
            </div>
          </div>
        </div>
      );
    default:
      return <DashboardSkeleton />;
  }
};

// Wrapper components with Suspense and proper error boundaries
export const LazyDashboard = () => (
  <Suspense fallback={<LoadingFallback type="dashboard" />}>
    <Dashboard />
  </Suspense>
);

export const LazyExpenses = () => (
  <Suspense fallback={<LoadingFallback type="expenses" />}>
    <Expenses />
  </Suspense>
);

export const LazyIncome = () => (
  <Suspense fallback={<LoadingFallback type="income" />}>
    <Income />
  </Suspense>
);

export const LazyBudgets = () => (
  <Suspense fallback={<LoadingFallback type="budgets" />}>
    <Budgets />
  </Suspense>
);

export const LazyAnalytics = () => (
  <Suspense fallback={<LoadingFallback type="analytics" />}>
    <Analytics />
  </Suspense>
);

export const LazyProfile = () => (
  <Suspense fallback={<LoadingFallback type="profile" />}>
    <Profile />
  </Suspense>
);

// Error boundary for lazy components
export class LazyComponentErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Lazy component loading error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="p-8 text-center">
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-6">
            <h3 className="text-lg font-medium text-red-800 dark:text-red-200 mb-2">
              Failed to load component
            </h3>
            <p className="text-red-600 dark:text-red-400 mb-4">
              There was an error loading this page. Please try refreshing.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md transition-colors"
            >
              Refresh Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default {
  LazyDashboard,
  LazyExpenses,
  LazyIncome,
  LazyBudgets,
  LazyAnalytics,
  LazyProfile,
  LazyComponentErrorBoundary
};
