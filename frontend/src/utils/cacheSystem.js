// Advanced caching system for API data and computed values

class CacheManager {
  constructor() {
    this.cache = new Map();
    this.timestamps = new Map();
    this.defaultTTL = 5 * 60 * 1000; // 5 minutes default TTL
    this.maxSize = 100; // Maximum cache entries
  }

  // Set cache with TTL
  set(key, value, ttl = this.defaultTTL) {
    // Remove oldest entries if cache is full
    if (this.cache.size >= this.maxSize) {
      const oldestKey = this.cache.keys().next().value;
      this.delete(oldestKey);
    }

    this.cache.set(key, value);
    this.timestamps.set(key, Date.now() + ttl);
    
    if (process.env.NODE_ENV === 'development') {
      console.log(`💾 Cache SET: ${key} (TTL: ${ttl}ms)`);
    }
  }

  // Get from cache with expiry check
  get(key) {
    const timestamp = this.timestamps.get(key);
    
    if (!timestamp || Date.now() > timestamp) {
      this.delete(key);
      return null;
    }

    const value = this.cache.get(key);
    
    if (process.env.NODE_ENV === 'development') {
      console.log(`💾 Cache HIT: ${key}`);
    }
    
    return value;
  }

  // Delete cache entry
  delete(key) {
    this.cache.delete(key);
    this.timestamps.delete(key);
    
    if (process.env.NODE_ENV === 'development') {
      console.log(`💾 Cache DELETE: ${key}`);
    }
  }

  // Clear all cache
  clear() {
    this.cache.clear();
    this.timestamps.clear();
    
    if (process.env.NODE_ENV === 'development') {
      console.log('💾 Cache CLEARED');
    }
  }

  // Get cache statistics
  getStats() {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      keys: Array.from(this.cache.keys())
    };
  }

  // Check if key exists and is valid
  has(key) {
    const timestamp = this.timestamps.get(key);
    return timestamp && Date.now() <= timestamp;
  }
}

// Global cache instance
const cache = new CacheManager();

// Cache keys for different data types
export const CACHE_KEYS = {
  DASHBOARD_DATA: 'dashboard_data',
  EXPENSES: 'expenses',
  INCOME: 'income',
  BUDGETS: 'budgets',
  USER_PROFILE: 'user_profile',
  CURRENCY_RATES: 'currency_rates',
  ANALYTICS_DATA: 'analytics_data'
};

// Cache TTL configurations (in milliseconds)
export const CACHE_TTL = {
  SHORT: 1 * 60 * 1000,      // 1 minute
  MEDIUM: 5 * 60 * 1000,     // 5 minutes
  LONG: 15 * 60 * 1000,      // 15 minutes
  VERY_LONG: 60 * 60 * 1000  // 1 hour
};

// Cached API wrapper
export const cachedApiCall = async (key, apiFunction, ttl = CACHE_TTL.MEDIUM) => {
  // Check cache first
  const cachedData = cache.get(key);
  if (cachedData) {
    return cachedData;
  }

  try {
    // Make API call
    const data = await apiFunction();
    
    // Cache the result
    cache.set(key, data, ttl);
    
    return data;
  } catch (error) {
    console.error(`API call failed for ${key}:`, error);
    throw error;
  }
};

// Memoized computation cache
export const memoizedCompute = (key, computeFunction, dependencies = [], ttl = CACHE_TTL.SHORT) => {
  // Create a dependency-based cache key
  const depKey = `${key}_${JSON.stringify(dependencies)}`;
  
  // Check cache
  const cachedResult = cache.get(depKey);
  if (cachedResult) {
    return cachedResult;
  }

  // Compute and cache
  const result = computeFunction();
  cache.set(depKey, result, ttl);
  
  return result;
};

// Invalidate cache by pattern
export const invalidateCache = (pattern) => {
  const keys = Array.from(cache.cache.keys());
  const keysToDelete = keys.filter(key => 
    typeof pattern === 'string' ? key.includes(pattern) : pattern.test(key)
  );
  
  keysToDelete.forEach(key => cache.delete(key));
  
  if (process.env.NODE_ENV === 'development') {
    console.log(`💾 Cache INVALIDATED: ${keysToDelete.length} keys matching "${pattern}"`);
  }
};

// Export cache instance as default
export default cache;
