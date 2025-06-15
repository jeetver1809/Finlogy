import React from 'react';
import { Skeleton, TableRowSkeleton } from './Skeleton';

const TableSkeleton = ({
  rows = 5,
  columns = 4,
  headers = [],
  className = ''
}) => {
  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 overflow-hidden ${className}`}>
      <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        {/* Table Header */}
        <thead className="bg-gray-50 dark:bg-gray-700">
          <tr>
            {headers.length > 0 ? (
              headers.map((header, index) => (
                <th key={index} className="px-6 py-3 text-left">
                  <Skeleton width="w-20" height="h-4" />
                </th>
              ))
            ) : (
              Array.from({ length: columns }).map((_, index) => (
                <th key={index} className="px-6 py-3 text-left">
                  <Skeleton width="w-20" height="h-4" />
                </th>
              ))
            )}
          </tr>
        </thead>

        {/* Table Body */}
        <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
          {Array.from({ length: rows }).map((_, index) => (
            <TableRowSkeleton key={index} columns={columns} />
          ))}
        </tbody>
      </table>
    </div>
  );
};

// Expenses Table Skeleton
const ExpensesTableSkeleton = ({ rows = 5 }) => {
  return (
    <TableSkeleton
      rows={rows}
      columns={5}
      headers={['Description', 'Category', 'Amount', 'Date', 'Actions']}
    />
  );
};

// Income Table Skeleton
const IncomeTableSkeleton = ({ rows = 5 }) => {
  return (
    <TableSkeleton
      rows={rows}
      columns={5}
      headers={['Description', 'Source', 'Amount', 'Date', 'Actions']}
    />
  );
};

// Enhanced Table Row with specific content types
const EnhancedTableRowSkeleton = ({ type = 'expense' }) => {
  return (
    <tr className="border-b border-gray-200 hover:bg-gray-50">
      {/* Description Column */}
      <td className="px-6 py-4">
        <div className="space-y-1">
          <Skeleton width="w-32" height="h-4" />
          <Skeleton width="w-24" height="h-3" />
        </div>
      </td>
      
      {/* Category/Source Column */}
      <td className="px-6 py-4">
        <div className="inline-flex items-center">
          <Skeleton width="w-16" height="h-6" rounded="rounded-full" />
        </div>
      </td>
      
      {/* Amount Column */}
      <td className="px-6 py-4">
        <Skeleton width="w-20" height="h-4" />
      </td>
      
      {/* Date Column */}
      <td className="px-6 py-4">
        <Skeleton width="w-16" height="h-4" />
      </td>
      
      {/* Actions Column */}
      <td className="px-6 py-4">
        <div className="flex space-x-2">
          <Skeleton width="w-8" height="h-4" />
          <Skeleton width="w-12" height="h-4" />
        </div>
      </td>
    </tr>
  );
};

// Enhanced Expenses Table Skeleton with dark mode
const EnhancedExpensesTableSkeleton = ({ rows = 5 }) => {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 overflow-hidden">
      <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead className="bg-gray-50 dark:bg-gray-700">
          <tr>
            <th className="px-6 py-3 text-left">
              <Skeleton width="w-20" height="h-4" />
            </th>
            <th className="px-6 py-3 text-left">
              <Skeleton width="w-16" height="h-4" />
            </th>
            <th className="px-6 py-3 text-left">
              <Skeleton width="w-12" height="h-4" />
            </th>
            <th className="px-6 py-3 text-left">
              <Skeleton width="w-8" height="h-4" />
            </th>
            <th className="px-6 py-3 text-left">
              <Skeleton width="w-14" height="h-4" />
            </th>
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
          {Array.from({ length: rows }).map((_, index) => (
            <EnhancedTableRowSkeleton key={index} type="expense" />
          ))}
        </tbody>
      </table>
    </div>
  );
};

// Enhanced Income Table Skeleton with dark mode
const EnhancedIncomeTableSkeleton = ({ rows = 5 }) => {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 overflow-hidden">
      <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead className="bg-gray-50 dark:bg-gray-700">
          <tr>
            <th className="px-6 py-3 text-left">
              <Skeleton width="w-20" height="h-4" />
            </th>
            <th className="px-6 py-3 text-left">
              <Skeleton width="w-12" height="h-4" />
            </th>
            <th className="px-6 py-3 text-left">
              <Skeleton width="w-12" height="h-4" />
            </th>
            <th className="px-6 py-3 text-left">
              <Skeleton width="w-8" height="h-4" />
            </th>
            <th className="px-6 py-3 text-left">
              <Skeleton width="w-14" height="h-4" />
            </th>
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
          {Array.from({ length: rows }).map((_, index) => (
            <EnhancedTableRowSkeleton key={index} type="income" />
          ))}
        </tbody>
      </table>
    </div>
  );
};

export {
  TableSkeleton,
  ExpensesTableSkeleton,
  IncomeTableSkeleton,
  EnhancedExpensesTableSkeleton,
  EnhancedIncomeTableSkeleton
};
