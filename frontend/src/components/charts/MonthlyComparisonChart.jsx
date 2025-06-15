import React, { memo, useMemo } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts';
import { useTheme } from '../../context/ThemeContext';
import { useCurrency } from '../../context/CurrencyContext';
import { ChartErrorBoundary } from '../ErrorBoundary';

const MonthlyComparisonChart = memo(({ data, height = 300 }) => {
  const { isDark } = useTheme();
  const { formatAmount } = useCurrency();

  // Memoized chart configuration
  const chartConfig = useMemo(() => ({
    colors: {
      income: isDark ? '#10B981' : '#059669',
      expenses: isDark ? '#EF4444' : '#DC2626',
      savings: isDark ? '#3B82F6' : '#2563EB',
      grid: isDark ? '#374151' : '#E5E7EB',
      text: isDark ? '#D1D5DB' : '#6B7280'
    }
  }), [isDark]);

  // Custom tooltip
  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
          <p className="text-sm font-medium text-gray-900 dark:text-white mb-3">
            {label}
          </p>
          <div className="space-y-2">
            {payload.map((entry, index) => (
              <div key={index} className="flex items-center justify-between space-x-4">
                <div className="flex items-center space-x-2">
                  <div 
                    className="w-3 h-3 rounded-sm"
                    style={{ backgroundColor: entry.color }}
                  />
                  <span className="text-sm text-gray-600 dark:text-gray-300 capitalize">
                    {entry.dataKey}:
                  </span>
                </div>
                <span className="text-sm font-semibold text-gray-900 dark:text-white">
                  {formatAmount(entry.value, { showSymbol: true })}
                </span>
              </div>
            ))}
            {/* Calculate and show savings rate */}
            {payload.length >= 2 && (
              <div className="pt-2 border-t border-gray-200 dark:border-gray-600">
                <div className="flex items-center justify-between space-x-4">
                  <span className="text-sm text-gray-600 dark:text-gray-300">
                    Savings Rate:
                  </span>
                  <span className="text-sm font-semibold text-gray-900 dark:text-white">
                    {payload[0].payload.income > 0 
                      ? Math.round((payload[0].payload.savings / payload[0].payload.income) * 100)
                      : 0
                    }%
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      );
    }
    return null;
  };

  // Custom bar shape for hover effects
  const CustomBar = (props) => {
    const {
      fill,
      x,
      y,
      width,
      height,
      // Filter out Recharts-specific props that shouldn't go to DOM
      tooltipPayload,
      tooltipPosition,
      dataKey,
      ...rest
    } = props;

    return (
      <rect
        x={x}
        y={y}
        width={width}
        height={height}
        fill={fill}
        className="transition-all duration-200 hover:brightness-110 cursor-pointer"
        style={{
          filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.1))'
        }}
      />
    );
  };

  // If no data, show empty state
  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <div className="w-16 h-16 mx-auto mb-4 bg-gray-100 dark:bg-gray-700 rounded-full flex items-center justify-center">
            <svg className="w-8 h-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <p className="text-gray-500 dark:text-gray-400">No monthly data available</p>
        </div>
      </div>
    );
  }

  return (
    <ChartErrorBoundary>
      <div className="w-full">
        <ResponsiveContainer width="100%" height={height}>
          <BarChart
            data={data}
            margin={{ top: 20, right: 30, left: 20, bottom: 20 }}
            barCategoryGap="20%"
          >
          <CartesianGrid 
            strokeDasharray="3 3" 
            stroke={chartConfig.colors.grid}
            opacity={0.3}
          />
          <XAxis 
            dataKey="month" 
            stroke={chartConfig.colors.text}
            fontSize={12}
            tickLine={false}
            axisLine={false}
            angle={-45}
            textAnchor="end"
            height={60}
          />
          <YAxis 
            stroke={chartConfig.colors.text}
            fontSize={12}
            tickLine={false}
            axisLine={false}
            tickFormatter={(value) => formatAmount(value, { showSymbol: true, minimumFractionDigits: 0, maximumFractionDigits: 0 })}
          />
          <Tooltip content={<CustomTooltip />} />
          <Legend 
            wrapperStyle={{ 
              color: chartConfig.colors.text,
              fontSize: '14px',
              paddingTop: '20px'
            }}
          />
          
          {/* Income Bars */}
          <Bar
            dataKey="income"
            fill={chartConfig.colors.income}
            name="Income"
            radius={[2, 2, 0, 0]}
            shape={<CustomBar />}
          />
          
          {/* Expenses Bars */}
          <Bar
            dataKey="expenses"
            fill={chartConfig.colors.expenses}
            name="Expenses"
            radius={[2, 2, 0, 0]}
            shape={<CustomBar />}
          />
          
          {/* Savings Bars */}
          <Bar
            dataKey="savings"
            fill={chartConfig.colors.savings}
            name="Savings"
            radius={[2, 2, 0, 0]}
            shape={<CustomBar />}
          />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </ChartErrorBoundary>
  );
});

MonthlyComparisonChart.displayName = 'MonthlyComparisonChart';

export default MonthlyComparisonChart;
