import React from 'react';
import { Skeleton, CardSkeleton } from '../ui/Skeleton';

// Analytics Overview Cards Skeleton
const AnalyticsOverviewSkeleton = () => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
      {[...Array(4)].map((_, index) => (
        <CardSkeleton key={index} className="space-y-4">
          {/* Icon and Title */}
          <div className="flex items-center space-x-3">
            <Skeleton width="w-10" height="h-10" rounded="rounded-lg" />
            <div className="space-y-1">
              <Skeleton width="w-20" height="h-4" />
              <Skeleton width="w-16" height="h-3" />
            </div>
          </div>
          
          {/* Value */}
          <Skeleton width="w-24" height="h-8" />
          
          {/* Change Indicator */}
          <div className="flex items-center space-x-2">
            <Skeleton width="w-4" height="h-4" rounded="rounded-full" />
            <Skeleton width="w-16" height="h-3" />
          </div>
        </CardSkeleton>
      ))}
    </div>
  );
};

// Chart Skeleton Component
const ChartSkeleton = ({ height = "h-80", title = "" }) => {
  return (
    <CardSkeleton className="space-y-4">
      {/* Chart Title */}
      {title && (
        <div className="flex justify-between items-center">
          <Skeleton width="w-32" height="h-6" />
          <Skeleton width="w-20" height="h-4" />
        </div>
      )}
      
      {/* Chart Area */}
      <div className={`${height} bg-gray-100 dark:bg-gray-700 rounded-lg animate-pulse relative overflow-hidden`}>
        {/* Shimmer effect for chart */}
        <div className="absolute inset-0 -translate-x-full animate-shimmer bg-gradient-to-r from-gray-100 via-gray-50 to-gray-100 dark:from-gray-700 dark:via-gray-600 dark:to-gray-700" />
        
        {/* Mock chart elements */}
        <div className="absolute bottom-4 left-4 right-4 flex justify-between items-end space-x-2">
          {[...Array(7)].map((_, i) => (
            <div
              key={i}
              className="bg-gray-200 dark:bg-gray-600 rounded-t"
              style={{
                height: `${Math.random() * 60 + 20}%`,
                width: '12%'
              }}
            />
          ))}
        </div>
      </div>
      
      {/* Chart Legend */}
      <div className="flex justify-center space-x-6">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="flex items-center space-x-2">
            <Skeleton width="w-3" height="h-3" rounded="rounded-full" />
            <Skeleton width="w-16" height="h-3" />
          </div>
        ))}
      </div>
    </CardSkeleton>
  );
};

// Top Categories Skeleton
const TopCategoriesSkeleton = () => {
  return (
    <CardSkeleton className="space-y-4">
      {/* Header */}
      <div className="flex justify-between items-center">
        <Skeleton width="w-32" height="h-6" />
        <Skeleton width="w-16" height="h-4" />
      </div>
      
      {/* Category List */}
      <div className="space-y-4">
        {[...Array(5)].map((_, index) => (
          <div key={index} className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Skeleton width="w-8" height="h-8" rounded="rounded-lg" />
              <div className="space-y-1">
                <Skeleton width="w-20" height="h-4" />
                <Skeleton width="w-16" height="h-3" />
              </div>
            </div>
            <div className="text-right space-y-1">
              <Skeleton width="w-16" height="h-4" />
              <Skeleton width="w-12" height="h-3" />
            </div>
          </div>
        ))}
      </div>
    </CardSkeleton>
  );
};

// Budget Performance Skeleton
const BudgetPerformanceSkeleton = () => {
  return (
    <CardSkeleton className="space-y-4">
      {/* Header */}
      <Skeleton width="w-36" height="h-6" />
      
      {/* Budget Items */}
      <div className="space-y-4">
        {[...Array(4)].map((_, index) => (
          <div key={index} className="space-y-2">
            <div className="flex justify-between items-center">
              <Skeleton width="w-24" height="h-4" />
              <Skeleton width="w-16" height="h-4" />
            </div>
            {/* Progress Bar */}
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <Skeleton 
                width={`w-${Math.floor(Math.random() * 8) + 2}/12`} 
                height="h-2" 
                rounded="rounded-full" 
              />
            </div>
            <div className="flex justify-between text-xs">
              <Skeleton width="w-12" height="h-3" />
              <Skeleton width="w-16" height="h-3" />
            </div>
          </div>
        ))}
      </div>
    </CardSkeleton>
  );
};

// Main Analytics Skeleton
const AnalyticsSkeleton = () => {
  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center space-y-4 sm:space-y-0">
        <Skeleton width="w-32" height="h-8" />
        <Skeleton width="w-48" height="h-10" rounded="rounded-lg" />
      </div>
      
      {/* Overview Cards */}
      <AnalyticsOverviewSkeleton />
      
      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Income vs Expenses Chart */}
        <ChartSkeleton height="h-80" title="Income vs Expenses" />
        
        {/* Category Breakdown */}
        <ChartSkeleton height="h-80" title="Category Breakdown" />
      </div>
      
      {/* Bottom Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Monthly Comparison */}
        <div className="lg:col-span-2">
          <ChartSkeleton height="h-64" title="Monthly Comparison" />
        </div>
        
        {/* Top Categories */}
        <TopCategoriesSkeleton />
      </div>
      
      {/* Budget Performance */}
      <BudgetPerformanceSkeleton />
    </div>
  );
};

export default AnalyticsSkeleton;
export {
  AnalyticsOverviewSkeleton,
  ChartSkeleton,
  TopCategoriesSkeleton,
  BudgetPerformanceSkeleton
};
