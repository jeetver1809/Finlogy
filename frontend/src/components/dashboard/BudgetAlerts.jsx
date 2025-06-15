import React from 'react';
import { ExclamationTriangleIcon } from '@heroicons/react/24/outline';

const BudgetAlerts = ({ alerts }) => {
  if (!alerts || alerts.length === 0) {
    return null;
  }

  const getAlertColor = (status) => {
    switch (status) {
      case 'exceeded':
        return 'bg-red-50 border-red-200 text-red-800 dark:bg-red-900/20 dark:border-red-800 dark:text-red-300';
      case 'warning':
        return 'bg-yellow-50 border-yellow-200 text-yellow-800 dark:bg-yellow-900/20 dark:border-yellow-800 dark:text-yellow-300';
      default:
        return 'bg-blue-50 border-blue-200 text-blue-800 dark:bg-blue-900/20 dark:border-blue-800 dark:text-blue-300';
    }
  };

  return (
    <div className="card p-6">
      <div className="flex items-center mb-4">
        <ExclamationTriangleIcon className="h-5 w-5 text-yellow-500 mr-2" />
        <h3 className="text-lg font-medium text-gray-900 dark:text-white">
          Budget Alerts
        </h3>
      </div>
      
      <div className="space-y-3">
        {alerts.map((alert, index) => (
          <div
            key={alert.budgetId}
            className={`p-4 rounded-lg border ${getAlertColor(alert.status)} interactive-card hover-brighten transition-all duration-200`}
            style={{ animationDelay: `${index * 100}ms` }}
          >
            <div className="flex items-center justify-between">
              <div>
                <h4 className="font-medium">{alert.budgetName}</h4>
                <p className="text-sm opacity-75">
                  {alert.category} • {alert.percentage}% used
                </p>
              </div>
              <div className="text-right">
                <p className="font-medium">
                  ${alert.spent.toFixed(2)} / ${alert.amount.toFixed(2)}
                </p>
                <p className="text-sm opacity-75">
                  ${alert.remaining.toFixed(2)} remaining
                </p>
              </div>
            </div>
            
            {/* Progress bar */}
            <div className="mt-3">
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div
                  className={`h-2 rounded-full ${
                    alert.status === 'exceeded'
                      ? 'bg-red-500'
                      : alert.status === 'warning'
                      ? 'bg-yellow-500'
                      : 'bg-blue-500'
                  }`}
                  style={{ width: `${Math.min(alert.percentage, 100)}%` }}
                />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default BudgetAlerts;
