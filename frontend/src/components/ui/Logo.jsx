import React from 'react';
import { useTheme } from '../../context/ThemeContext';

const Logo = ({
  size = 'md',
  showText = true,
  className = '',
  textClassName = '',
  iconClassName = '',
  useCustomIcon = false
}) => {
  const { isDark } = useTheme();

  const sizeClasses = {
    sm: {
      icon: 'w-6 h-6',
      text: 'text-2xl font-bold leading-relaxed',
      container: 'gap-3'
    },
    md: {
      icon: 'w-10 h-10',
      text: 'text-4xl font-extrabold leading-relaxed',
      container: 'gap-4'
    },
    lg: {
      icon: 'w-14 h-14',
      text: 'text-6xl font-extrabold leading-relaxed',
      container: 'gap-5'
    },
    xl: {
      icon: 'w-18 h-18',
      text: 'text-7xl font-extrabold leading-relaxed',
      container: 'gap-6'
    }
  };

  const currentSize = sizeClasses[size];

  // Professional Finlogy icon with theme awareness
  const FinlogyIcon = () => {
    if (useCustomIcon) {
      // Use logo3.png for the Finlogy logo with circular crop to remove outer blue area
      return (
        <div className={`${currentSize.icon} ${iconClassName} relative`}>
          <img
            src="/icons/light mode icons/logo3.png"
            alt="Finlogy"
            className="w-full h-full object-cover rounded-full"
            style={{
              clipPath: 'circle(50%)',
              objectPosition: 'center'
            }}
            onError={(e) => {
              // Fallback to logo1.png if logo3.png fails to load
              e.target.src = "/icons/light mode icons/logo1.png";
            }}
          />
        </div>
      );
    }

    // Fallback to custom SVG icon
    return (
      <div className={`${currentSize.icon} ${iconClassName} relative`}>
        <svg
          viewBox="0 0 24 24"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="w-full h-full"
        >
          {/* Background circle with gradient */}
          <defs>
            <linearGradient id="finlogyGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor={isDark ? "#182471" : "#1E40AF"} />
              <stop offset="100%" stopColor={isDark ? "#2664C8" : "#3B82F6"} />
            </linearGradient>
          </defs>

          {/* Main circle background */}
          <circle
            cx="12"
            cy="12"
            r="11"
            fill="url(#finlogyGradient)"
            className="drop-shadow-sm"
          />

          {/* Financial chart icon */}
          <path
            d="M8 16h2v-4H8v4zm3-8h2v8h-2V8zm3-4h2v12h-2V4zm3 6h2v6h-2v-6z"
            fill="white"
            className="opacity-90"
          />

          {/* Accent dot */}
          <circle
            cx="18"
            cy="6"
            r="1.5"
            fill={isDark ? "#10B981" : "#059669"}
            className="opacity-80"
          />
        </svg>
      </div>
    );
  };

  return (
    <div className={`flex items-center ${currentSize.container} ${className}`}>
      <FinlogyIcon />
      {showText && (
        <div className="flex items-center">
          <span
            className={`
              ${currentSize.text}
              ${textClassName}
              text-white
              font-inter tracking-tight
              block py-1
            `}
            style={{
              lineHeight: '1.2',
              paddingBottom: '0.125rem'
            }}
          >
            Finlogy
          </span>
        </div>
      )}
    </div>
  );
};

export default Logo;
