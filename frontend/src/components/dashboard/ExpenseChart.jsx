import React, { useState, memo, useMemo } from 'react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend
} from 'recharts';
import { useTheme } from '../../context/ThemeContext';
import { useCurrency } from '../../context/CurrencyContext';
import { ChartErrorBoundary } from '../ErrorBoundary';

const ExpenseChart = ({ data }) => {
  const [hoveredSegment, setHoveredSegment] = useState(null);
  const chartRef = useRef(null);

  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-gray-500 dark:text-gray-400">No expense data available</p>
      </div>
    );
  }

  const colors = [
    '#3B82F6', // blue
    '#EF4444', // red
    '#10B981', // green
    '#F59E0B', // yellow
    '#8B5CF6', // purple
    '#F97316', // orange
    '#EC4899', // pink
    '#6B7280', // gray
  ];

  const chartData = {
    labels: data.map(item => item._id.charAt(0).toUpperCase() + item._id.slice(1)),
    datasets: [
      {
        data: data.map(item => item.total),
        backgroundColor: colors.slice(0, data.length).map((color, index) =>
          hoveredSegment === index ? color : color + 'CC'
        ),
        borderColor: colors.slice(0, data.length),
        borderWidth: hoveredSegment !== null ? 3 : 2,
        hoverBackgroundColor: colors.slice(0, data.length),
        hoverBorderColor: colors.slice(0, data.length),
        hoverBorderWidth: 4,
        hoverOffset: 8,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    animation: {
      animateRotate: true,
      animateScale: true,
      duration: 1000,
      easing: 'easeOutQuart',
    },
    interaction: {
      intersect: false,
      mode: 'index',
    },
    onHover: (event, elements) => {
      if (elements.length > 0) {
        setHoveredSegment(elements[0].index);
      } else {
        setHoveredSegment(null);
      }
    },
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          padding: 20,
          usePointStyle: true,
          color: document.documentElement.classList.contains('dark') ? '#D1D5DB' : '#374151',
          generateLabels: function(chart) {
            const data = chart.data;
            if (data.labels.length && data.datasets.length) {
              return data.labels.map((label, i) => {
                const meta = chart.getDatasetMeta(0);
                const style = meta.controller.getStyle(i);
                const total = data.datasets[0].data.reduce((a, b) => a + b, 0);
                const value = data.datasets[0].data[i];
                const percentage = ((value / total) * 100).toFixed(1);

                return {
                  text: `${label}: ${percentage}%`,
                  fillStyle: style.backgroundColor,
                  strokeStyle: style.borderColor,
                  lineWidth: style.borderWidth,
                  pointStyle: 'circle',
                  hidden: isNaN(value) || meta.data[i].hidden,
                  index: i
                };
              });
            }
            return [];
          }
        },
        onHover: (event, legendItem) => {
          setHoveredSegment(legendItem.index);
        },
        onLeave: () => {
          setHoveredSegment(null);
        }
      },
      tooltip: {
        enabled: true,
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        titleColor: '#fff',
        bodyColor: '#fff',
        borderColor: 'rgba(255, 255, 255, 0.1)',
        borderWidth: 1,
        cornerRadius: 8,
        displayColors: true,
        callbacks: {
          label: function(context) {
            const total = context.dataset.data.reduce((a, b) => a + b, 0);
            const percentage = ((context.parsed / total) * 100).toFixed(1);
            return `${context.label}: $${context.parsed.toFixed(2)} (${percentage}%)`;
          },
        },
      },
    },
  };

  return (
    <div className="chart-container relative">
      <Doughnut
        ref={chartRef}
        data={chartData}
        options={options}
      />

      {/* Interactive Legend */}
      {hoveredSegment !== null && (
        <div className="absolute top-4 right-4 bg-white dark:bg-gray-800 p-3 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 animate-slide-in-up">
          <div className="text-sm font-medium text-gray-900 dark:text-white">
            {data[hoveredSegment]._id.charAt(0).toUpperCase() + data[hoveredSegment]._id.slice(1)}
          </div>
          <div className="text-lg font-bold text-gray-900 dark:text-white">
            ${data[hoveredSegment].total.toFixed(2)}
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">
            {((data[hoveredSegment].total / data.reduce((sum, item) => sum + item.total, 0)) * 100).toFixed(1)}% of total
          </div>
        </div>
      )}
    </div>
  );
};

export default ExpenseChart;
