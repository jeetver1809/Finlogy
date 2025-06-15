// Performance monitoring utilities

// Measure component render time
export const measureRenderTime = (componentName) => {
  const startTime = performance.now();
  
  return () => {
    const endTime = performance.now();
    const renderTime = endTime - startTime;
    
    if (process.env.NODE_ENV === 'development') {
      console.log(`🚀 ${componentName} render time: ${renderTime.toFixed(2)}ms`);
      
      // Warn if render time is too high
      if (renderTime > 16) { // 60fps = 16.67ms per frame
        console.warn(`⚠️ ${componentName} render time exceeds 16ms (${renderTime.toFixed(2)}ms)`);
      }
    }
    
    return renderTime;
  };
};

// Debounce function for performance optimization
export const debounce = (func, wait, immediate = false) => {
  let timeout;
  
  return function executedFunction(...args) {
    const later = () => {
      timeout = null;
      if (!immediate) func(...args);
    };
    
    const callNow = immediate && !timeout;
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
    
    if (callNow) func(...args);
  };
};

// Throttle function for scroll/resize events
export const throttle = (func, limit) => {
  let inThrottle;
  
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
};

// Memoization utility for expensive calculations
export const memoize = (fn, getKey = (...args) => JSON.stringify(args)) => {
  const cache = new Map();
  
  return (...args) => {
    const key = getKey(...args);
    
    if (cache.has(key)) {
      return cache.get(key);
    }
    
    const result = fn(...args);
    cache.set(key, result);
    
    // Prevent memory leaks by limiting cache size
    if (cache.size > 100) {
      const firstKey = cache.keys().next().value;
      cache.delete(firstKey);
    }
    
    return result;
  };
};

// Lazy loading utility for images
export const lazyLoadImage = (src, placeholder = '') => {
  return new Promise((resolve, reject) => {
    const img = new Image();
    
    img.onload = () => resolve(src);
    img.onerror = () => reject(new Error(`Failed to load image: ${src}`));
    
    img.src = src;
  });
};

// Bundle size analyzer (development only)
export const analyzeBundleSize = () => {
  if (process.env.NODE_ENV === 'development') {
    const scripts = document.querySelectorAll('script[src]');
    const styles = document.querySelectorAll('link[rel="stylesheet"]');
    
    let totalSize = 0;
    
    scripts.forEach(script => {
      fetch(script.src)
        .then(response => response.blob())
        .then(blob => {
          const size = blob.size;
          totalSize += size;
          console.log(`📦 Script: ${script.src.split('/').pop()} - ${(size / 1024).toFixed(2)}KB`);
        })
        .catch(() => {}); // Ignore CORS errors
    });
    
    styles.forEach(style => {
      fetch(style.href)
        .then(response => response.blob())
        .then(blob => {
          const size = blob.size;
          totalSize += size;
          console.log(`🎨 Style: ${style.href.split('/').pop()} - ${(size / 1024).toFixed(2)}KB`);
        })
        .catch(() => {}); // Ignore CORS errors
    });
    
    setTimeout(() => {
      console.log(`📊 Total estimated bundle size: ${(totalSize / 1024).toFixed(2)}KB`);
    }, 2000);
  }
};

// Performance observer for Core Web Vitals
export const observeWebVitals = () => {
  if (typeof window !== 'undefined' && 'PerformanceObserver' in window) {
    // Largest Contentful Paint (LCP)
    const lcpObserver = new PerformanceObserver((list) => {
      const entries = list.getEntries();
      const lastEntry = entries[entries.length - 1];
      console.log('🎯 LCP:', lastEntry.startTime.toFixed(2) + 'ms');
    });
    
    try {
      lcpObserver.observe({ entryTypes: ['largest-contentful-paint'] });
    } catch (e) {
      // Browser doesn't support LCP
    }
    
    // First Input Delay (FID)
    const fidObserver = new PerformanceObserver((list) => {
      const entries = list.getEntries();
      entries.forEach(entry => {
        console.log('⚡ FID:', entry.processingStart - entry.startTime + 'ms');
      });
    });
    
    try {
      fidObserver.observe({ entryTypes: ['first-input'] });
    } catch (e) {
      // Browser doesn't support FID
    }
    
    // Cumulative Layout Shift (CLS)
    let clsValue = 0;
    const clsObserver = new PerformanceObserver((list) => {
      const entries = list.getEntries();
      entries.forEach(entry => {
        if (!entry.hadRecentInput) {
          clsValue += entry.value;
        }
      });
      console.log('📐 CLS:', clsValue.toFixed(4));
    });
    
    try {
      clsObserver.observe({ entryTypes: ['layout-shift'] });
    } catch (e) {
      // Browser doesn't support CLS
    }
  }
};

// Memory usage monitoring
export const monitorMemoryUsage = () => {
  if (process.env.NODE_ENV === 'development' && 'memory' in performance) {
    const memory = performance.memory;
    
    console.log('🧠 Memory Usage:', {
      used: `${(memory.usedJSHeapSize / 1024 / 1024).toFixed(2)}MB`,
      total: `${(memory.totalJSHeapSize / 1024 / 1024).toFixed(2)}MB`,
      limit: `${(memory.jsHeapSizeLimit / 1024 / 1024).toFixed(2)}MB`
    });
    
    // Warn if memory usage is high
    const usagePercentage = (memory.usedJSHeapSize / memory.jsHeapSizeLimit) * 100;
    if (usagePercentage > 80) {
      console.warn(`⚠️ High memory usage: ${usagePercentage.toFixed(1)}%`);
    }
  }
};

// Initialize performance monitoring
export const initPerformanceMonitoring = () => {
  if (process.env.NODE_ENV === 'development') {
    console.log('🚀 Performance monitoring initialized');
    
    // Monitor web vitals
    observeWebVitals();
    
    // Monitor memory usage every 30 seconds
    setInterval(monitorMemoryUsage, 30000);
    
    // Analyze bundle size on load
    setTimeout(analyzeBundleSize, 1000);
  }
};

export default {
  measureRenderTime,
  debounce,
  throttle,
  memoize,
  lazyLoadImage,
  analyzeBundleSize,
  observeWebVitals,
  monitorMemoryUsage,
  initPerformanceMonitoring
};
