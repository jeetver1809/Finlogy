/**
 * 🎨 CATEGORY CONFIGURATION SYSTEM
 * 
 * Centralized configuration for budget and expense categories
 * Includes icons, colors, and visual styling for consistency
 */

import {
  // Education
  AcademicCapIcon,
  BookOpenIcon,
  
  // Travel
  GlobeAltIcon,
  MapPinIcon,
  
  // Food & Dining
  BuildingStorefrontIcon,
  CakeIcon,
  
  // Transportation
  TruckIcon,
  BoltIcon,
  
  // Entertainment
  FilmIcon,
  MusicalNoteIcon,
  
  // Healthcare
  HeartIcon,
  PlusCircleIcon,
  
  // Shopping
  ShoppingBagIcon,
  GiftIcon,
  
  // Utilities
  HomeIcon,
  LightBulbIcon,
  
  // Finance
  BanknotesIcon,
  CreditCardIcon,
  
  // Work
  BriefcaseIcon,
  ComputerDesktopIcon,
  
  // Personal
  UserIcon,
  SparklesIcon,
  
  // Other
  EllipsisHorizontalIcon,
  TagIcon,
  ShieldCheckIcon
} from '@heroicons/react/24/outline';

// Category configuration with icons, colors, and metadata
export const CATEGORY_CONFIG = {
  // Education Categories
  education: {
    name: 'Education',
    icon: AcademicCapIcon,
    colors: {
      light: {
        primary: '#3B82F6',      // Blue-500
        secondary: '#DBEAFE',    // Blue-100
        text: '#1E40AF',         // Blue-700
        border: '#93C5FD'        // Blue-300
      },
      dark: {
        primary: '#2563EB',      // Blue-600 (dimmed further)
        secondary: '#1E293B',    // Much more muted (slate-800)
        text: '#7DD3FC',         // Blue-300 with reduced opacity
        border: '#1D4ED8'        // Blue-700 (darker border)
      }
    },
    gradient: 'from-blue-500 to-indigo-600',
    description: 'Learning and educational expenses'
  },
  
  books: {
    name: 'Books & Learning',
    icon: BookOpenIcon,
    colors: {
      light: {
        primary: '#6366F1',      // Indigo-500
        secondary: '#E0E7FF',    // Indigo-100
        text: '#4338CA',         // Indigo-700
        border: '#A5B4FC'        // Indigo-300
      },
      dark: {
        primary: '#6366F1',      // Indigo-500 (more muted)
        secondary: '#312E81',    // Indigo-800
        text: '#A5B4FC',         // Indigo-300 (less bright)
        border: '#4F46E5'        // Indigo-600 (darker border)
      }
    },
    gradient: 'from-indigo-500 to-purple-600',
    description: 'Books, courses, and learning materials'
  },

  // Travel Categories
  travel: {
    name: 'Travel',
    icon: GlobeAltIcon,
    colors: {
      light: {
        primary: '#10B981',      // Emerald-500
        secondary: '#D1FAE5',    // Emerald-100
        text: '#047857',         // Emerald-700
        border: '#6EE7B7'        // Emerald-300
      },
      dark: {
        primary: '#059669',      // Emerald-600 (dimmed further)
        secondary: '#1F2937',    // Much more muted (gray-800)
        text: '#4ADE80',         // Emerald-400 with reduced intensity
        border: '#047857'        // Emerald-700 (darker border)
      }
    },
    gradient: 'from-emerald-500 to-teal-600',
    description: 'Vacation, trips, and travel expenses'
  },
  
  vacation: {
    name: 'Vacation',
    icon: MapPinIcon,
    colors: {
      light: {
        primary: '#14B8A6',      // Teal-500
        secondary: '#CCFBF1',    // Teal-100
        text: '#0F766E',         // Teal-700
        border: '#5EEAD4'        // Teal-300
      },
      dark: {
        primary: '#14B8A6',      // Teal-500 (more muted)
        secondary: '#134E4A',    // Teal-800
        text: '#5EEAD4',         // Teal-300 (less bright)
        border: '#0F766E'        // Teal-600 (darker border)
      }
    },
    gradient: 'from-teal-500 to-cyan-600',
    description: 'Holiday and vacation expenses'
  },

  // Food & Dining Categories
  food: {
    name: 'Food & Dining',
    icon: BuildingStorefrontIcon,
    colors: {
      light: {
        primary: '#F59E0B',      // Amber-500
        secondary: '#FEF3C7',    // Amber-100
        text: '#D97706',         // Amber-600
        border: '#FCD34D'        // Amber-300
      },
      dark: {
        primary: '#D97706',      // Amber-600 (dimmed further)
        secondary: '#1F2937',    // Much more muted (gray-800)
        text: '#FBBF24',         // Amber-400 with reduced intensity
        border: '#B45309'        // Amber-700 (darker border)
      }
    },
    gradient: 'from-amber-500 to-orange-600',
    description: 'Restaurants, groceries, and dining'
  },
  
  groceries: {
    name: 'Groceries',
    icon: CakeIcon,
    colors: {
      light: {
        primary: '#EF4444',      // Red-500
        secondary: '#FEE2E2',    // Red-100
        text: '#DC2626',         // Red-600
        border: '#FCA5A5'        // Red-300
      },
      dark: {
        primary: '#EF4444',      // Red-500 (more muted)
        secondary: '#7F1D1D',    // Red-800
        text: '#FCA5A5',         // Red-300 (less bright)
        border: '#DC2626'        // Red-600 (darker border)
      }
    },
    gradient: 'from-red-500 to-pink-600',
    description: 'Food shopping and groceries'
  },

  // Transportation Categories
  transportation: {
    name: 'Transportation',
    icon: TruckIcon,
    colors: {
      light: {
        primary: '#8B5CF6',      // Violet-500
        secondary: '#EDE9FE',    // Violet-100
        text: '#7C3AED',         // Violet-600
        border: '#C4B5FD'        // Violet-300
      },
      dark: {
        primary: '#8B5CF6',      // Violet-500 (more muted)
        secondary: '#1F2937',    // Much more muted (gray-800)
        text: '#C4B5FD',         // Violet-300 (less bright)
        border: '#7C3AED'        // Violet-600 (darker border)
      }
    },
    gradient: 'from-violet-500 to-purple-600',
    description: 'Car, public transport, fuel'
  },
  
  fuel: {
    name: 'Fuel & Gas',
    icon: BoltIcon,
    colors: {
      light: {
        primary: '#EC4899',      // Pink-500
        secondary: '#FCE7F3',    // Pink-100
        text: '#DB2777',         // Pink-600
        border: '#F9A8D4'        // Pink-300
      },
      dark: {
        primary: '#EC4899',      // Pink-500 (more muted)
        secondary: '#831843',    // Pink-800
        text: '#F9A8D4',         // Pink-300 (less bright)
        border: '#DB2777'        // Pink-600 (darker border)
      }
    },
    gradient: 'from-pink-500 to-rose-600',
    description: 'Vehicle fuel and energy costs'
  },

  // Entertainment Categories
  entertainment: {
    name: 'Entertainment',
    icon: FilmIcon,
    colors: {
      light: {
        primary: '#06B6D4',      // Cyan-500
        secondary: '#CFFAFE',    // Cyan-100
        text: '#0891B2',         // Cyan-600
        border: '#67E8F9'        // Cyan-300
      },
      dark: {
        primary: '#06B6D4',      // Cyan-500 (more muted)
        secondary: '#164E63',    // Cyan-800
        text: '#67E8F9',         // Cyan-300 (less bright)
        border: '#0891B2'        // Cyan-600 (darker border)
      }
    },
    gradient: 'from-cyan-500 to-blue-600',
    description: 'Movies, games, and fun activities'
  },
  
  music: {
    name: 'Music & Media',
    icon: MusicalNoteIcon,
    colors: {
      light: {
        primary: '#8B5CF6',      // Violet-500
        secondary: '#EDE9FE',    // Violet-100
        text: '#7C3AED',         // Violet-600
        border: '#C4B5FD'        // Violet-300
      },
      dark: {
        primary: '#8B5CF6',      // Violet-500 (more muted)
        secondary: '#4C1D95',    // Violet-800
        text: '#C4B5FD',         // Violet-300 (less bright)
        border: '#7C3AED'        // Violet-600 (darker border)
      }
    },
    gradient: 'from-violet-500 to-indigo-600',
    description: 'Music, streaming, and media subscriptions'
  },

  // Healthcare Categories
  healthcare: {
    name: 'Healthcare',
    icon: HeartIcon,
    colors: {
      light: {
        primary: '#EF4444',      // Red-500
        secondary: '#FEE2E2',    // Red-100
        text: '#DC2626',         // Red-600
        border: '#FCA5A5'        // Red-300
      },
      dark: {
        primary: '#EF4444',      // Red-500 (more muted)
        secondary: '#1F2937',    // Much more muted (gray-800)
        text: '#FCA5A5',         // Red-300 (less bright)
        border: '#DC2626'        // Red-600 (darker border)
      }
    },
    gradient: 'from-red-500 to-rose-600',
    description: 'Medical expenses and health insurance'
  },
  
  medical: {
    name: 'Medical',
    icon: PlusCircleIcon,
    colors: {
      light: {
        primary: '#F97316',      // Orange-500
        secondary: '#FED7AA',    // Orange-100
        text: '#EA580C',         // Orange-600
        border: '#FDBA74'        // Orange-300
      },
      dark: {
        primary: '#F97316',      // Orange-500 (more muted)
        secondary: '#9A3412',    // Orange-800
        text: '#FDBA74',         // Orange-300 (less bright)
        border: '#EA580C'        // Orange-600 (darker border)
      }
    },
    gradient: 'from-orange-500 to-red-600',
    description: 'Doctor visits, medications, treatments'
  },

  // Shopping Categories
  shopping: {
    name: 'Shopping',
    icon: ShoppingBagIcon,
    colors: {
      light: {
        primary: '#A855F7',      // Purple-500
        secondary: '#F3E8FF',    // Purple-100
        text: '#9333EA',         // Purple-600
        border: '#D8B4FE'        // Purple-300
      },
      dark: {
        primary: '#A855F7',      // Purple-500 (more muted)
        secondary: '#581C87',    // Purple-800
        text: '#D8B4FE',         // Purple-300 (less bright)
        border: '#9333EA'        // Purple-600 (darker border)
      }
    },
    gradient: 'from-purple-500 to-pink-600',
    description: 'Clothing, accessories, and retail'
  },
  
  gifts: {
    name: 'Gifts',
    icon: GiftIcon,
    colors: {
      light: {
        primary: '#EC4899',      // Pink-500
        secondary: '#FCE7F3',    // Pink-100
        text: '#DB2777',         // Pink-600
        border: '#F9A8D4'        // Pink-300
      },
      dark: {
        primary: '#EC4899',      // Pink-500 (more muted)
        secondary: '#831843',    // Pink-800
        text: '#F9A8D4',         // Pink-300 (less bright)
        border: '#DB2777'        // Pink-600 (darker border)
      }
    },
    gradient: 'from-pink-500 to-purple-600',
    description: 'Presents and gift expenses'
  },

  // Utilities Categories
  utilities: {
    name: 'Utilities',
    icon: HomeIcon,
    colors: {
      light: {
        primary: '#64748B',      // Slate-500
        secondary: '#F1F5F9',    // Slate-100
        text: '#475569',         // Slate-600
        border: '#CBD5E1'        // Slate-300
      },
      dark: {
        primary: '#94A3B8',      // Slate-400
        secondary: '#1F2937',    // Much more muted (gray-800)
        text: '#E2E8F0',         // Slate-200
        border: '#64748B'        // Slate-500
      }
    },
    gradient: 'from-slate-500 to-gray-600',
    description: 'Electricity, water, internet, phone'
  },
  
  electricity: {
    name: 'Electricity',
    icon: LightBulbIcon,
    colors: {
      light: {
        primary: '#FACC15',      // Yellow-400
        secondary: '#FEF9C3',    // Yellow-100
        text: '#CA8A04',         // Yellow-600
        border: '#FDE047'        // Yellow-300
      },
      dark: {
        primary: '#FACC15',      // Yellow-400 (more muted)
        secondary: '#713F12',    // Yellow-800
        text: '#FDE047',         // Yellow-300 (less bright)
        border: '#CA8A04'        // Yellow-600 (darker border)
      }
    },
    gradient: 'from-yellow-400 to-orange-500',
    description: 'Electrical bills and energy costs'
  },

  // Housing Categories
  housing: {
    name: 'Housing',
    icon: HomeIcon,
    colors: {
      light: {
        primary: '#7C3AED',      // Violet-600
        secondary: '#EDE9FE',    // Violet-100
        text: '#6D28D9',         // Violet-700
        border: '#C4B5FD'        // Violet-300
      },
      dark: {
        primary: '#8B5CF6',      // Violet-500
        secondary: '#2D1B69',    // Violet-900
        text: '#C4B5FD',         // Violet-300
        border: '#7C3AED'        // Violet-600
      }
    },
    gradient: 'from-violet-600 to-purple-700',
    description: 'Rent, mortgage, property taxes, maintenance'
  },

  // Insurance Categories
  insurance: {
    name: 'Insurance',
    icon: ShieldCheckIcon,
    colors: {
      light: {
        primary: '#059669',      // Emerald-600
        secondary: '#D1FAE5',    // Emerald-100
        text: '#047857',         // Emerald-700
        border: '#6EE7B7'        // Emerald-300
      },
      dark: {
        primary: '#10B981',      // Emerald-500
        secondary: '#022C22',    // Emerald-900
        text: '#6EE7B7',         // Emerald-300
        border: '#059669'        // Emerald-600
      }
    },
    gradient: 'from-emerald-600 to-green-700',
    description: 'Health, auto, home, life insurance premiums'
  },

  // Finance Categories
  savings: {
    name: 'Savings',
    icon: BanknotesIcon,
    colors: {
      light: {
        primary: '#10B981',      // Emerald-500
        secondary: '#D1FAE5',    // Emerald-100
        text: '#047857',         // Emerald-700
        border: '#6EE7B7'        // Emerald-300
      },
      dark: {
        primary: '#10B981',      // Emerald-500 (more muted)
        secondary: '#064E3B',    // Emerald-800
        text: '#6EE7B7',         // Emerald-300 (less bright)
        border: '#059669'        // Emerald-600 (darker border)
      }
    },
    gradient: 'from-emerald-500 to-green-600',
    description: 'Emergency fund and savings goals'
  },
  
  investments: {
    name: 'Investments',
    icon: CreditCardIcon,
    colors: {
      light: {
        primary: '#059669',      // Emerald-600
        secondary: '#ECFDF5',    // Green-50
        text: '#065F46',         // Emerald-800
        border: '#34D399'        // Emerald-400
      },
      dark: {
        primary: '#10B981',      // Emerald-500
        secondary: '#022C22',    // Emerald-900
        text: '#6EE7B7',         // Emerald-300
        border: '#059669'        // Emerald-600
      }
    },
    gradient: 'from-green-600 to-emerald-700',
    description: 'Stocks, bonds, and investment accounts'
  },

  // Business Categories
  business: {
    name: 'Business',
    icon: BriefcaseIcon,
    colors: {
      light: {
        primary: '#374151',      // Gray-700
        secondary: '#F9FAFB',    // Gray-50
        text: '#1F2937',         // Gray-800
        border: '#D1D5DB'        // Gray-300
      },
      dark: {
        primary: '#9CA3AF',      // Gray-400
        secondary: '#111827',    // Gray-900
        text: '#F3F4F6',         // Gray-100
        border: '#6B7280'        // Gray-500
      }
    },
    gradient: 'from-gray-700 to-slate-800',
    description: 'Business expenses and professional costs'
  },
  
  office: {
    name: 'Office Supplies',
    icon: ComputerDesktopIcon,
    colors: {
      light: {
        primary: '#6B7280',      // Gray-500
        secondary: '#F3F4F6',    // Gray-100
        text: '#374151',         // Gray-700
        border: '#D1D5DB'        // Gray-300
      },
      dark: {
        primary: '#9CA3AF',      // Gray-400
        secondary: '#1F2937',    // Gray-800
        text: '#E5E7EB',         // Gray-200
        border: '#6B7280'        // Gray-500
      }
    },
    gradient: 'from-gray-500 to-slate-600',
    description: 'Office equipment and supplies'
  },

  // Personal Categories
  personal: {
    name: 'Personal Care',
    icon: UserIcon,
    colors: {
      light: {
        primary: '#8B5CF6',      // Violet-500
        secondary: '#EDE9FE',    // Violet-100
        text: '#7C3AED',         // Violet-600
        border: '#C4B5FD'        // Violet-300
      },
      dark: {
        primary: '#8B5CF6',      // Violet-500 (more muted)
        secondary: '#4C1D95',    // Violet-800
        text: '#C4B5FD',         // Violet-300 (less bright)
        border: '#7C3AED'        // Violet-600 (darker border)
      }
    },
    gradient: 'from-violet-500 to-purple-600',
    description: 'Personal care and wellness'
  },
  
  fitness: {
    name: 'Fitness & Wellness',
    icon: SparklesIcon,
    colors: {
      light: {
        primary: '#06B6D4',      // Cyan-500
        secondary: '#CFFAFE',    // Cyan-100
        text: '#0891B2',         // Cyan-600
        border: '#67E8F9'        // Cyan-300
      },
      dark: {
        primary: '#06B6D4',      // Cyan-500 (more muted)
        secondary: '#164E63',    // Cyan-800
        text: '#67E8F9',         // Cyan-300 (less bright)
        border: '#0891B2'        // Cyan-600 (darker border)
      }
    },
    gradient: 'from-cyan-500 to-teal-600',
    description: 'Gym, sports, and wellness activities'
  },

  // Other Categories
  other: {
    name: 'Other',
    icon: EllipsisHorizontalIcon,
    colors: {
      light: {
        primary: '#6B7280',      // Gray-500
        secondary: '#F3F4F6',    // Gray-100
        text: '#374151',         // Gray-700
        border: '#D1D5DB'        // Gray-300
      },
      dark: {
        primary: '#9CA3AF',      // Gray-400
        secondary: '#1F2937',    // Gray-800
        text: '#E5E7EB',         // Gray-200
        border: '#6B7280'        // Gray-500
      }
    },
    gradient: 'from-gray-500 to-slate-600',
    description: 'Miscellaneous expenses'
  },
  
  miscellaneous: {
    name: 'Miscellaneous',
    icon: TagIcon,
    colors: {
      light: {
        primary: '#78716C',      // Stone-500
        secondary: '#F5F5F4',    // Stone-100
        text: '#57534E',         // Stone-600
        border: '#D6D3D1'        // Stone-300
      },
      dark: {
        primary: '#A8A29E',      // Stone-400
        secondary: '#1C1917',    // Stone-900
        text: '#E7E5E4',         // Stone-200
        border: '#78716C'        // Stone-500
      }
    },
    gradient: 'from-stone-500 to-gray-600',
    description: 'Uncategorized expenses'
  }
};

// Helper function to get category configuration
export const getCategoryConfig = (categoryKey) => {
  const normalizedKey = categoryKey?.toLowerCase().replace(/[^a-z0-9]/g, '');
  return CATEGORY_CONFIG[normalizedKey] || CATEGORY_CONFIG.other;
};

// Helper function to get category icon
export const getCategoryIcon = (categoryKey) => {
  const config = getCategoryConfig(categoryKey);
  return config.icon;
};

// Helper function to get category colors for current theme
export const getCategoryColors = (categoryKey, isDark = false) => {
  const config = getCategoryConfig(categoryKey);
  return isDark ? config.colors.dark : config.colors.light;
};

// Helper function to get category gradient
export const getCategoryGradient = (categoryKey) => {
  const config = getCategoryConfig(categoryKey);
  return config.gradient;
};

// Get all available categories
export const getAllCategories = () => {
  return Object.keys(CATEGORY_CONFIG).map(key => ({
    key,
    ...CATEGORY_CONFIG[key]
  }));
};

// Get categories by type (for grouping)
export const getCategoriesByType = () => {
  return {
    essential: ['utilities', 'electricity', 'food', 'groceries', 'healthcare', 'medical', 'transportation', 'fuel'],
    lifestyle: ['entertainment', 'music', 'shopping', 'gifts', 'travel', 'vacation', 'personal', 'fitness'],
    financial: ['savings', 'investments'],
    education: ['education', 'books'],
    work: ['work', 'office'],
    other: ['other', 'miscellaneous']
  };
};
