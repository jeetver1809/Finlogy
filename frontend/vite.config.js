import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],

  // Build optimizations
  build: {
    // Enable minification
    minify: 'terser',

    // Optimize chunk splitting
    rollupOptions: {
      output: {
        // Manual chunk splitting for better caching
        manualChunks: {
          // Vendor chunks
          'react-vendor': ['react', 'react-dom'],
          'ui-vendor': ['@headlessui/react', '@heroicons/react'],

          // Feature chunks
          'dashboard': ['./src/pages/Dashboard.jsx'],
          'transactions': ['./src/pages/Expenses.jsx', './src/pages/Income.jsx'],
          'budgets': ['./src/pages/Budgets.jsx'],
          'forms': [
            './src/components/forms/ExpenseForm.jsx',
            './src/components/forms/IncomeForm.jsx',
            './src/components/forms/BudgetForm.jsx'
          ],
          'ui-components': [
            './src/components/ui/StatCard.jsx',
            './src/components/ui/BudgetCard.jsx',
            './src/components/ui/ProgressBar.jsx',
            './src/components/ui/CurrencyDisplay.jsx'
          ]
        },

        // Optimize asset naming for caching
        chunkFileNames: (chunkInfo) => {
          const facadeModuleId = chunkInfo.facadeModuleId
            ? chunkInfo.facadeModuleId.split('/').pop().replace('.jsx', '').replace('.js', '')
            : 'chunk';
          return `js/${facadeModuleId}-[hash].js`;
        },
        assetFileNames: (assetInfo) => {
          const info = assetInfo.name.split('.');
          const ext = info[info.length - 1];
          if (/\.(css)$/.test(assetInfo.name)) {
            return `css/[name]-[hash].${ext}`;
          }
          if (/\.(png|jpe?g|svg|gif|tiff|bmp|ico)$/i.test(assetInfo.name)) {
            return `images/[name]-[hash].${ext}`;
          }
          return `assets/[name]-[hash].${ext}`;
        }
      }
    },

    // Optimize bundle size
    target: 'esnext',
    sourcemap: false, // Disable in production for smaller bundles

    // CSS optimization
    cssCodeSplit: true,

    // Terser options for better minification
    terserOptions: {
      compress: {
        drop_console: true, // Remove console.log in production
        drop_debugger: true,
        pure_funcs: ['console.log', 'console.info', 'console.debug']
      },
      mangle: {
        safari10: true
      }
    }
  },

  // Development optimizations
  server: {
    // Enable HMR for faster development
    hmr: true,

    // Optimize dependency pre-bundling
    force: false
  },

  // Dependency optimization
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      '@headlessui/react',
      '@heroicons/react/24/outline',
      '@heroicons/react/24/solid',
      'react-hot-toast'
    ],
    exclude: []
  },

  // CSS preprocessing optimizations
  css: {
    devSourcemap: false, // Disable CSS sourcemaps in dev for faster builds
    preprocessorOptions: {
      css: {
        charset: false // Remove charset to reduce CSS size
      }
    }
  },

  // Asset handling
  assetsInclude: ['**/*.png', '**/*.jpg', '**/*.jpeg', '**/*.gif', '**/*.svg', '**/*.webp']
})
