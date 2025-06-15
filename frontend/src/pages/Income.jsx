import React from 'react';
import { PlusIcon } from '@heroicons/react/24/outline';

const Income = () => {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          Income
        </h1>
        <button className="btn-primary">
          <PlusIcon className="h-5 w-5 mr-2" />
          Add Income
        </button>
      </div>

      {/* Content */}
      <div className="card p-8 text-center">
        <p className="text-gray-500 dark:text-gray-400">
          Income management page - Coming soon!
        </p>
      </div>
    </div>
  );
};

export default Income;
