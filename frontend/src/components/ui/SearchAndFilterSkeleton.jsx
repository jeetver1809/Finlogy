import React from 'react';

const SearchAndFilterSkeleton = () => {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-4 mb-6 animate-pulse">
      {/* Search Bar Skeleton */}
      <div className="flex flex-col sm:flex-row gap-4 mb-4">
        <div className="flex-1 relative">
          <div className="w-full h-12 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
        </div>
        
        <div className="flex gap-2">
          {/* Filter Button Skeleton */}
          <div className="hidden sm:block w-32 h-12 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
          {/* Mobile Filter Button Skeleton */}
          <div className="sm:hidden w-24 h-12 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
          {/* Clear Button Skeleton */}
          <div className="w-20 h-12 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
        </div>
      </div>

      {/* Results Summary Skeleton */}
      <div className="flex items-center justify-between mb-4">
        <div className="w-48 h-4 bg-gray-200 dark:bg-gray-700 rounded"></div>
        <div className="w-24 h-4 bg-gray-200 dark:bg-gray-700 rounded"></div>
      </div>

      {/* Desktop Filter Controls Skeleton */}
      <div className="hidden sm:block border-t border-gray-200 dark:border-gray-600 pt-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {/* Category Filter Skeleton */}
          <div>
            <div className="w-16 h-4 bg-gray-200 dark:bg-gray-700 rounded mb-2"></div>
            <div className="w-full h-10 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
          </div>
          
          {/* Date From Skeleton */}
          <div>
            <div className="w-20 h-4 bg-gray-200 dark:bg-gray-700 rounded mb-2"></div>
            <div className="w-full h-10 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
          </div>
          
          {/* Date To Skeleton */}
          <div>
            <div className="w-16 h-4 bg-gray-200 dark:bg-gray-700 rounded mb-2"></div>
            <div className="w-full h-10 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
          </div>
          
          {/* Amount Range Skeleton */}
          <div>
            <div className="w-24 h-4 bg-gray-200 dark:bg-gray-700 rounded mb-2"></div>
            <div className="flex space-x-2">
              <div className="w-full h-10 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
              <div className="w-full h-10 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
            </div>
          </div>
        </div>

        {/* Active Filters Skeleton */}
        <div className="mt-6 pt-4 border-t border-gray-200 dark:border-gray-600">
          <div className="flex flex-wrap gap-2">
            <div className="w-20 h-4 bg-gray-200 dark:bg-gray-700 rounded mb-2"></div>
            <div className="w-24 h-6 bg-gray-200 dark:bg-gray-700 rounded-full"></div>
            <div className="w-32 h-6 bg-gray-200 dark:bg-gray-700 rounded-full"></div>
            <div className="w-28 h-6 bg-gray-200 dark:bg-gray-700 rounded-full"></div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SearchAndFilterSkeleton;
