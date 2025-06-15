import React from 'react';

// Base Skeleton component with shimmer animation and dark mode support
const Skeleton = ({
  className = '',
  width = 'w-full',
  height = 'h-4',
  rounded = 'rounded',
  animate = true
}) => {
  return (
    <div
      className={`
        bg-gray-200 dark:bg-gray-700
        ${width}
        ${height}
        ${rounded}
        ${animate ? 'animate-pulse' : ''}
        ${className}
      `}
    />
  );
};

// Shimmer effect component for more advanced animations with dark mode
const ShimmerSkeleton = ({
  className = '',
  width = 'w-full',
  height = 'h-4',
  rounded = 'rounded'
}) => {
  return (
    <div
      className={`
        relative overflow-hidden bg-gray-200 dark:bg-gray-700
        ${width}
        ${height}
        ${rounded}
        ${className}
      `}
    >
      {/* Light mode shimmer */}
      <div className="absolute inset-0 -translate-x-full animate-shimmer bg-gradient-to-r from-gray-200 via-white to-gray-200 dark:hidden" />
      {/* Dark mode shimmer */}
      <div className="absolute inset-0 -translate-x-full animate-shimmer bg-gradient-to-r from-gray-700 via-gray-600 to-gray-700 hidden dark:block" />
    </div>
  );
};

// Text line skeleton
const TextSkeleton = ({ 
  lines = 1, 
  className = '', 
  lineHeight = 'h-4',
  spacing = 'space-y-2' 
}) => {
  return (
    <div className={`${spacing} ${className}`}>
      {Array.from({ length: lines }).map((_, index) => (
        <Skeleton 
          key={index}
          height={lineHeight}
          width={index === lines - 1 && lines > 1 ? 'w-3/4' : 'w-full'}
        />
      ))}
    </div>
  );
};

// Avatar/Circle skeleton
const AvatarSkeleton = ({ size = 'w-10 h-10', className = '' }) => {
  return (
    <Skeleton 
      className={className}
      width={size.split(' ')[0]}
      height={size.split(' ')[1]}
      rounded="rounded-full"
    />
  );
};

// Button skeleton
const ButtonSkeleton = ({ 
  size = 'medium', 
  className = '',
  variant = 'primary' 
}) => {
  const sizeClasses = {
    small: 'h-8 w-20',
    medium: 'h-10 w-24',
    large: 'h-12 w-32'
  };

  return (
    <Skeleton 
      className={className}
      width={sizeClasses[size].split(' ')[1]}
      height={sizeClasses[size].split(' ')[0]}
      rounded="rounded-md"
    />
  );
};

// Card skeleton wrapper with dark mode support
const CardSkeleton = ({ children, className = '' }) => {
  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 p-6 ${className}`}>
      {children}
    </div>
  );
};

// Table row skeleton with dark mode support
const TableRowSkeleton = ({ columns = 4, className = '' }) => {
  return (
    <tr className={`border-b border-gray-200 dark:border-gray-700 ${className}`}>
      {Array.from({ length: columns }).map((_, index) => (
        <td key={index} className="px-6 py-4">
          <Skeleton height="h-4" />
        </td>
      ))}
    </tr>
  );
};

// Progress bar skeleton with dark mode support
const ProgressSkeleton = ({ className = '' }) => {
  return (
    <div className={`w-full ${className}`}>
      <div className="flex justify-between mb-1">
        <Skeleton width="w-20" height="h-3" />
        <Skeleton width="w-16" height="h-3" />
      </div>
      <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
        <Skeleton width="w-1/2" height="h-2" rounded="rounded-full" />
      </div>
    </div>
  );
};

export {
  Skeleton,
  ShimmerSkeleton,
  TextSkeleton,
  AvatarSkeleton,
  ButtonSkeleton,
  CardSkeleton,
  TableRowSkeleton,
  ProgressSkeleton
};
