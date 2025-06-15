import React from 'react';
import { Skeleton, CardSkeleton, TextSkeleton, ProgressSkeleton } from './Skeleton';

// Summary Card Skeleton for Dashboard
const SummaryCardSkeleton = ({ className = '' }) => {
  return (
    <CardSkeleton className={className}>
      <div className="space-y-3">
        {/* Title */}
        <Skeleton width="w-24" height="h-5" />
        
        {/* Amount */}
        <Skeleton width="w-32" height="h-8" />
        
        {/* Subtitle */}
        <Skeleton width="w-16" height="h-4" />
      </div>
    </CardSkeleton>
  );
};

// Recent Transaction Item Skeleton with dark mode support
const RecentTransactionSkeleton = ({ className = '' }) => {
  return (
    <div className={`flex items-center justify-between py-3 border-b border-gray-100 dark:border-gray-700 last:border-b-0 ${className}`}>
      <div className="flex items-center space-x-3">
        {/* Category Badge */}
        <Skeleton width="w-16" height="h-6" rounded="rounded-full" />

        <div className="space-y-1">
          {/* Title */}
          <Skeleton width="w-24" height="h-4" />
          {/* Date */}
          <Skeleton width="w-16" height="h-3" />
        </div>
      </div>

      {/* Amount */}
      <Skeleton width="w-20" height="h-4" />
    </div>
  );
};

// Recent Transactions Section Skeleton
const RecentTransactionsSkeleton = ({ items = 5, className = '' }) => {
  return (
    <CardSkeleton className={className}>
      <div className="space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <Skeleton width="w-32" height="h-6" />
          <Skeleton width="w-16" height="h-4" />
        </div>
        
        {/* Transaction List */}
        <div className="space-y-1">
          {Array.from({ length: items }).map((_, index) => (
            <RecentTransactionSkeleton key={index} />
          ))}
        </div>
      </div>
    </CardSkeleton>
  );
};

// Budget Overview Item Skeleton
const BudgetOverviewItemSkeleton = ({ className = '' }) => {
  return (
    <div className={`space-y-3 ${className}`}>
      {/* Budget Header */}
      <div className="flex justify-between items-center">
        <Skeleton width="w-20" height="h-4" />
        <Skeleton width="w-24" height="h-4" />
      </div>
      
      {/* Progress Bar */}
      <div className="space-y-2">
        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
          <Skeleton width="w-3/5" height="h-2" rounded="rounded-full" />
        </div>
        
        {/* Progress Details */}
        <div className="flex justify-between text-xs">
          <Skeleton width="w-12" height="h-3" />
          <Skeleton width="w-16" height="h-3" />
        </div>
      </div>
    </div>
  );
};

// Budget Overview Section Skeleton
const BudgetOverviewSkeleton = ({ items = 3, className = '' }) => {
  return (
    <CardSkeleton className={className}>
      <div className="space-y-4">
        {/* Header */}
        <Skeleton width="w-28" height="h-6" />
        
        {/* Budget Items */}
        <div className="space-y-4">
          {Array.from({ length: items }).map((_, index) => (
            <BudgetOverviewItemSkeleton key={index} />
          ))}
        </div>
      </div>
    </CardSkeleton>
  );
};

// Complete Dashboard Skeleton
const DashboardSkeleton = () => {
  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div className="flex justify-between items-center">
        <Skeleton width="w-32" height="h-8" />
        <Skeleton width="w-24" height="h-10" rounded="rounded-md" />
      </div>
      
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <SummaryCardSkeleton />
        <SummaryCardSkeleton />
        <SummaryCardSkeleton />
      </div>
      
      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Recent Transactions */}
        <RecentTransactionsSkeleton />
        
        {/* Budget Overview */}
        <BudgetOverviewSkeleton />
      </div>
    </div>
  );
};

// Budget Card Skeleton for Budgets Page
const BudgetCardSkeleton = ({ className = '' }) => {
  return (
    <CardSkeleton className={className}>
      <div className="space-y-4">
        {/* Header */}
        <div className="flex justify-between items-start">
          <div className="space-y-2">
            <Skeleton width="w-28" height="h-5" />
            <Skeleton width="w-20" height="h-6" rounded="rounded-full" />
          </div>
          <div className="flex space-x-2">
            <Skeleton width="w-8" height="h-8" rounded="rounded" />
            <Skeleton width="w-8" height="h-8" rounded="rounded" />
          </div>
        </div>
        
        {/* Budget Progress */}
        <div className="space-y-2">
          <div className="flex justify-between">
            <Skeleton width="w-16" height="h-4" />
            <Skeleton width="w-20" height="h-4" />
          </div>
          
          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
            <Skeleton width="w-2/3" height="h-3" rounded="rounded-full" />
          </div>
          
          <div className="flex justify-between">
            <Skeleton width="w-12" height="h-3" />
            <Skeleton width="w-16" height="h-3" />
          </div>
        </div>
        
        {/* Budget Details */}
        <div className="pt-2 border-t border-gray-100 dark:border-gray-700 space-y-2">
          <div className="flex justify-between">
            <Skeleton width="w-16" height="h-3" />
            <Skeleton width="w-12" height="h-3" />
          </div>
          <div className="flex justify-between">
            <Skeleton width="w-20" height="h-3" />
            <Skeleton width="w-16" height="h-3" />
          </div>
        </div>
      </div>
    </CardSkeleton>
  );
};

// Budgets Grid Skeleton
const BudgetsGridSkeleton = ({ items = 6 }) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      {Array.from({ length: items }).map((_, index) => (
        <BudgetCardSkeleton key={index} />
      ))}
    </div>
  );
};

export {
  SummaryCardSkeleton,
  RecentTransactionsSkeleton,
  BudgetOverviewSkeleton,
  DashboardSkeleton,
  BudgetCardSkeleton,
  BudgetsGridSkeleton
};
