import React, { useState, useEffect } from 'react';
import { PlusIcon } from '@heroicons/react/24/outline';
import { budgetService } from '../services/budgetService';
import LoadingSpinner from '../components/ui/LoadingSpinner';

const Budgets = () => {
  const [budgets, setBudgets] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchBudgets();
  }, []);

  const fetchBudgets = async () => {
    try {
      setLoading(true);
      const response = await budgetService.getBudgets();
      setBudgets(response.data);
    } catch (error) {
      console.error('Error fetching budgets:', error);
    } finally {
      setLoading(false);
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

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          Budgets
        </h1>
        <button className="btn-primary">
          <PlusIcon className="h-5 w-5 mr-2" />
          Create Budget
        </button>
      </div>

      {/* Budgets Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {budgets.length === 0 ? (
          <div className="col-span-full card p-8 text-center">
            <p className="text-gray-500 dark:text-gray-400">No budgets found. Create your first budget to get started!</p>
          </div>
        ) : (
          budgets.map((budget) => {
            const { status } = getBudgetStatus(budget);
            const percentage = Math.min((budget.spent / budget.amount) * 100, 100);
            
            return (
              <div key={budget._id} className="card p-6 hover-glow">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    {budget.name}
                  </h3>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    status === 'exceeded' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300' :
                    status === 'warning' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300' :
                    'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
                  }`}>
                    {budget.category}
                  </span>
                </div>

                <div className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600 dark:text-gray-400">Spent</span>
                    <span className="font-medium text-gray-900 dark:text-white">
                      ₹{budget.spent?.toFixed(2) || '0.00'} / ₹{budget.amount.toFixed(2)}
                    </span>
                  </div>

                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full transition-all duration-300 ${getProgressBarColor(status)}`}
                      style={{ width: `${percentage}%` }}
                    />
                  </div>

                  <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400">
                    <span>{percentage.toFixed(1)}% used</span>
                    <span>₹{(budget.amount - (budget.spent || 0)).toFixed(2)} remaining</span>
                  </div>

                  {budget.description && (
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
                      {budget.description}
                    </p>
                  )}

                  <div className="flex justify-between pt-3 border-t border-gray-200 dark:border-gray-700">
                    <button className="text-primary-600 hover:text-primary-900 dark:text-primary-400 text-sm font-medium">
                      Edit
                    </button>
                    <button className="text-red-600 hover:text-red-900 dark:text-red-400 text-sm font-medium">
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export default Budgets;
