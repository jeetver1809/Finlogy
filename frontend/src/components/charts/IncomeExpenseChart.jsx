import React, { memo, useMemo } from 'react';
import {
  LineChart,
  Line,
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

const IncomeExpenseChart = memo(({ data, height = 300 }) => {
  const { isDark } = useTheme();
  const { formatAmount } = useCurrency();

  // Memoized chart configuration for performance
  const chartConfig = useMemo(() => ({
    colors: {
      income: isDark ? '#10B981' : '#059669',
      expenses: isDark ? '#EF4444' : '#DC2626',
      net: isDark ? '#3B82F6' : '#2563EB',
      grid: isDark ? '#374151' : '#E5E7EB',
      text: isDark ? '#D1D5DB' : '#6B7280'
    },
    tooltip: {
      backgroundColor: isDark ? '#1F2937' : '#FFFFFF',
      border: `1px solid ${isDark ? '#374151' : '#E5E7EB'}`,
      borderRadius: '8px',
      boxShadow: isDark 
        ? '0 10px 15px -3px rgba(0, 0, 0, 0.5)' 
        : '0 10px 15px -3px rgba(0, 0, 0, 0.1)'
    }
  }), [isDark]);

  // Custom tooltip component
  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div 
          className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700"
          style={chartConfig.tooltip}
        >
          <p className="text-sm font-medium text-gray-900 dark:text-white mb-2">
            {label}
          </p>
          {payload.map((entry, index) => (
            <div key={index} className="flex items-center justify-between space-x-4">
              <div className="flex items-center space-x-2">
                <div 
                  className="w-3 h-3 rounded-full"
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
        </div>
      );
    }
    return null;
  };

  // Custom dot component for better hover effects
  const CustomDot = ({ cx, cy, fill, payload, dataKey }) => {
    return (
      <circle
        cx={cx}
        cy={cy}
        r={4}
        fill={fill}
        stroke={fill}
        strokeWidth={2}
        className="transition-all duration-200 hover:r-6 cursor-pointer"
        style={{
          filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.1))',
          transition: 'all 0.2s ease-in-out'
        }}
      />
    );
  };

  return (
    <ChartErrorBoundary>
      <div className="w-full">
        <ResponsiveContainer width="100%" height={height}>
          <LineChart
            data={data}
            margin={{ top: 20, right: 30, left: 20, bottom: 20 }}
          >
          <CartesianGrid 
            strokeDasharray="3 3" 
            stroke={chartConfig.colors.grid}
            opacity={0.3}
          />
          <XAxis 
            dataKey="date" 
            stroke={chartConfig.colors.text}
            fontSize={12}
            tickLine={false}
            axisLine={false}
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
          
          {/* Income Line */}
          <Line
            type="monotone"
            dataKey="income"
            stroke={chartConfig.colors.income}
            strokeWidth={3}
            dot={<CustomDot />}
            activeDot={{ 
              r: 6, 
              stroke: chartConfig.colors.income,
              strokeWidth: 2,
              fill: chartConfig.colors.income
            }}
            name="Income"
          />
          
          {/* Expenses Line */}
          <Line
            type="monotone"
            dataKey="expenses"
            stroke={chartConfig.colors.expenses}
            strokeWidth={3}
            dot={<CustomDot />}
            activeDot={{ 
              r: 6, 
              stroke: chartConfig.colors.expenses,
              strokeWidth: 2,
              fill: chartConfig.colors.expenses
            }}
            name="Expenses"
          />
          
          {/* Net Income Line */}
          <Line
            type="monotone"
            dataKey="net"
            stroke={chartConfig.colors.net}
            strokeWidth={2}
            strokeDasharray="5 5"
            dot={false}
            activeDot={{ 
              r: 5, 
              stroke: chartConfig.colors.net,
              strokeWidth: 2,
              fill: chartConfig.colors.net
            }}
            name="Net"
          />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </ChartErrorBoundary>
  );
});

IncomeExpenseChart.displayName = 'IncomeExpenseChart';

export default IncomeExpenseChart;
