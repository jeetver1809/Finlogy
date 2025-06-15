import { useEffect, useCallback, useRef, useState } from 'react';
import { invalidateAnalyticsCache } from '../utils/analyticsIntegration';
import { formatCurrency } from '../utils/analyticsHelpers';
import cache from '../utils/cacheSystem';

// Custom hook for Analytics data synchronization
export const useAnalyticsSync = (dependencies = []) => {
  const previousDependencies = useRef(dependencies);
  const syncTimeoutRef = useRef(null);

  // Debounced cache invalidation
  const debouncedInvalidation = useCallback((type = 'all') => {
    if (syncTimeoutRef.current) {
      clearTimeout(syncTimeoutRef.current);
    }
    
    syncTimeoutRef.current = setTimeout(() => {
      invalidateAnalyticsCache(cache, type);
      
      // Dispatch custom event for components to listen to
      window.dispatchEvent(new CustomEvent('analyticsDataChanged', {
        detail: { type, timestamp: Date.now() }
      }));
      
      if (process.env.NODE_ENV === 'development') {
        console.log(`🔄 Analytics data synchronized (${type})`);
      }
    }, 300); // 300ms debounce
  }, []);

  // Check for dependency changes
  useEffect(() => {
    const hasChanged = dependencies.some((dep, index) => {
      const prevDep = previousDependencies.current[index];
      return JSON.stringify(dep) !== JSON.stringify(prevDep);
    });

    if (hasChanged) {
      // Determine what type of data changed
      let changeType = 'all';
      if (dependencies.length === 1) {
        const [data] = dependencies;
        if (data?.type) changeType = data.type;
        else if (Array.isArray(data)) {
          if (data.some(item => item.type === 'expense')) changeType = 'expenses';
          else if (data.some(item => item.type === 'income')) changeType = 'income';
          else if (data.some(item => item.amount && item.category)) changeType = 'budgets';
        }
      }

      debouncedInvalidation(changeType);
      previousDependencies.current = dependencies;
    }
  }, dependencies);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (syncTimeoutRef.current) {
        clearTimeout(syncTimeoutRef.current);
      }
    };
  }, []);

  return {
    invalidateCache: debouncedInvalidation,
    forceSync: () => debouncedInvalidation('all')
  };
};

// Hook for listening to analytics data changes
export const useAnalyticsDataListener = (callback, dependencies = []) => {
  useEffect(() => {
    const handleDataChange = (event) => {
      if (callback) {
        callback(event.detail);
      }
    };

    window.addEventListener('analyticsDataChanged', handleDataChange);
    
    return () => {
      window.removeEventListener('analyticsDataChanged', handleDataChange);
    };
  }, [callback, ...dependencies]);
};

// Hook for real-time analytics updates
export const useRealTimeAnalytics = (initialData = {}) => {
  const [data, setData] = useState(initialData);
  const [lastUpdated, setLastUpdated] = useState(Date.now());
  const [isStale, setIsStale] = useState(false);

  // Listen for data changes
  useAnalyticsDataListener(
    useCallback((changeInfo) => {
      setIsStale(true);
      setLastUpdated(changeInfo.timestamp);
      
      // Auto-refresh after a short delay
      setTimeout(() => {
        setIsStale(false);
        // Trigger data refresh in parent component
        window.dispatchEvent(new CustomEvent('refreshAnalyticsData'));
      }, 1000);
    }, [])
  );

  const updateData = useCallback((newData) => {
    setData(newData);
    setIsStale(false);
    setLastUpdated(Date.now());
  }, []);

  const markAsStale = useCallback(() => {
    setIsStale(true);
  }, []);

  return {
    data,
    lastUpdated,
    isStale,
    updateData,
    markAsStale
  };
};

// Hook for cross-section data correlation
export const useDataCorrelation = (primaryData, correlatedDataSources = []) => {
  const [correlations, setCorrelations] = useState([]);
  const [loading, setLoading] = useState(false);

  const calculateCorrelations = useCallback(async () => {
    if (!primaryData || correlatedDataSources.length === 0) {
      setCorrelations([]);
      return;
    }

    setLoading(true);
    
    try {
      const correlationResults = [];
      
      // Calculate correlations based on data type
      for (const source of correlatedDataSources) {
        let correlation = null;
        
        switch (source.type) {
          case 'budget-impact':
            if (primaryData.category && source.budgets) {
              const relatedBudget = source.budgets.find(b => 
                b.category === primaryData.category.toLowerCase().replace(/\s+/g, '-')
              );
              if (relatedBudget) {
                correlation = {
                  type: 'budget-impact',
                  title: `${relatedBudget.name} Budget Impact`,
                  description: `This expense affects your ${relatedBudget.name} budget`,
                  data: relatedBudget,
                  strength: 'high'
                };
              }
            }
            break;
            
          case 'category-trend':
            if (primaryData.category && source.expenses) {
              const categoryExpenses = source.expenses.filter(e => 
                e.category === primaryData.category
              );
              if (categoryExpenses.length > 0) {
                const totalAmount = categoryExpenses.reduce((sum, e) => sum + Math.abs(e.amount), 0);
                correlation = {
                  type: 'category-trend',
                  title: `${primaryData.category} Spending Trend`,
                  description: `Total spent in this category: ${formatCurrency(totalAmount)}`,
                  data: { category: primaryData.category, total: totalAmount, count: categoryExpenses.length },
                  strength: 'medium'
                };
              }
            }
            break;
            
          case 'income-expense-ratio':
            if (source.income && source.expenses) {
              const totalIncome = source.income.reduce((sum, i) => sum + i.amount, 0);
              const totalExpenses = source.expenses.reduce((sum, e) => sum + Math.abs(e.amount), 0);
              correlation = {
                type: 'income-expense-ratio',
                title: 'Income vs Expense Ratio',
                description: `Current ratio: ${totalIncome > 0 ? (totalExpenses / totalIncome * 100).toFixed(1) : 0}%`,
                data: { income: totalIncome, expenses: totalExpenses, ratio: totalIncome > 0 ? totalExpenses / totalIncome : 0 },
                strength: 'high'
              };
            }
            break;
            
          default:
            break;
        }
        
        if (correlation) {
          correlationResults.push(correlation);
        }
      }
      
      setCorrelations(correlationResults);
    } catch (error) {
      console.error('Error calculating data correlations:', error);
      setCorrelations([]);
    } finally {
      setLoading(false);
    }
  }, [primaryData, correlatedDataSources]);

  useEffect(() => {
    calculateCorrelations();
  }, [calculateCorrelations]);

  return {
    correlations,
    loading,
    recalculate: calculateCorrelations
  };
};

// Hook for contextual insights generation
export const useContextualInsights = (data, context = {}) => {
  const [insights, setInsights] = useState([]);

  const generateInsights = useCallback(() => {
    const newInsights = [];
    
    if (!data) {
      setInsights([]);
      return;
    }

    // Generate insights based on context
    switch (context.page) {
      case 'expenses':
        if (data.expenses && data.budgets) {
          // Budget alerts
          const overBudgetCategories = data.budgets.filter(b => {
            const spent = data.expenses
              .filter(e => e.category === b.category)
              .reduce((sum, e) => sum + Math.abs(e.amount), 0);
            return spent > b.amount;
          });
          
          if (overBudgetCategories.length > 0) {
            newInsights.push({
              icon: '⚠️',
              message: `${overBudgetCategories.length} budget${overBudgetCategories.length > 1 ? 's' : ''} exceeded`,
              value: `${overBudgetCategories.length}`,
              analyticsFilter: { type: 'budgets' },
              priority: 'high'
            });
          }
          
          // Top spending category
          const categoryTotals = {};
          data.expenses.forEach(e => {
            const category = e.category || 'Other';
            categoryTotals[category] = (categoryTotals[category] || 0) + Math.abs(e.amount);
          });
          
          const topCategory = Object.entries(categoryTotals)
            .sort(([,a], [,b]) => b - a)[0];
          
          if (topCategory) {
            newInsights.push({
              icon: '📊',
              message: `Top spending: ${topCategory[0]}`,
              value: formatCurrency(topCategory[1]),
              analyticsFilter: { category: topCategory[0] },
              priority: 'medium'
            });
          }
        }
        break;
        
      case 'income':
        if (data.income && data.expenses) {
          const totalIncome = data.income.reduce((sum, i) => sum + i.amount, 0);
          const totalExpenses = data.expenses.reduce((sum, e) => sum + Math.abs(e.amount), 0);
          const savingsRate = totalIncome > 0 ? ((totalIncome - totalExpenses) / totalIncome) * 100 : 0;
          
          newInsights.push({
            icon: '💰',
            message: 'Current savings rate',
            value: `${savingsRate.toFixed(1)}%`,
            analyticsFilter: { type: 'savings' },
            priority: savingsRate >= 20 ? 'low' : savingsRate >= 10 ? 'medium' : 'high'
          });
        }
        break;
        
      case 'budgets':
        if (data.budgets) {
          const onTrackCount = data.budgets.filter(b => {
            const percentage = (b.spent / b.amount) * 100;
            return percentage < (b.alertThreshold || 80);
          }).length;
          
          newInsights.push({
            icon: '🎯',
            message: 'Budgets on track',
            value: `${onTrackCount}/${data.budgets.length}`,
            analyticsFilter: { type: 'budgets' },
            priority: onTrackCount === data.budgets.length ? 'low' : 'medium'
          });
        }
        break;
        
      default:
        break;
    }
    
    setInsights(newInsights.sort((a, b) => {
      const priorityOrder = { high: 3, medium: 2, low: 1 };
      return priorityOrder[b.priority] - priorityOrder[a.priority];
    }));
  }, [data, context]);

  useEffect(() => {
    generateInsights();
  }, [generateInsights]);

  return insights;
};

export default {
  useAnalyticsSync,
  useAnalyticsDataListener,
  useRealTimeAnalytics,
  useDataCorrelation,
  useContextualInsights
};
