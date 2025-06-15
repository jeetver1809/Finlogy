# Enhanced SearchAndFilter Component

## Overview
The SearchAndFilter component has been completely redesigned to provide a superior user experience across all devices with modern UI patterns, accessibility features, and performance optimizations.

## Key Features

### 🔍 **Enhanced Search Component**
- **Mobile Optimization**: 44px minimum touch targets, responsive design
- **Keyboard Shortcuts**: Ctrl+K or Cmd+K to focus search
- **Autocomplete**: Real-time suggestions with keyboard navigation
- **Clear Button**: Easy search term clearing
- **Loading States**: Visual feedback during search operations
- **Accessibility**: Full ARIA support and screen reader compatibility

### 🎛️ **Advanced Filter System**
- **Mobile Modal**: Touch-friendly filter interface on mobile devices
- **Desktop Layout**: Horizontal filter layout for larger screens
- **Multi-select Support**: Individual filter removal with chips
- **Filter Persistence**: Maintains filters across page navigation
- **Real-time Application**: Debounced filter updates (300ms)
- **Filter Count Badges**: Visual indication of active filters

### 📱 **Cross-Platform Features**
- **Responsive Design**: Seamless experience on all screen sizes
- **Dark Mode Support**: Full dark theme compatibility
- **Results Display**: Clear result counts and "no results" states
- **Filter Breadcrumbs**: Visual representation of active filters
- **Performance Optimized**: Debounced search and memoized calculations

## Props API

```jsx
<SearchAndFilter
  // Core functionality
  onSearch={handleSearch}                    // Search callback function
  onFilter={handleFilter}                    // Filter callback function
  categories={categories}                    // Array of available categories
  
  // Customization
  placeholder="Search transactions..."       // Search input placeholder
  showAmountFilter={true}                   // Show/hide amount range filter
  
  // Results display
  resultCount={filteredItems.length}       // Current result count
  totalCount={allItems.length}             // Total item count
  
  // Enhanced features
  isLoading={false}                         // Loading state indicator
  suggestions={suggestions}                 // Array of search suggestions
  onSuggestionSelect={handleSuggestion}     // Suggestion selection callback
  persistFilters={true}                    // Enable filter persistence
  filterKey="unique-key"                   // Unique key for persistence
/>
```

## Usage Examples

### Basic Usage
```jsx
import SearchAndFilter from './components/ui/SearchAndFilter';

<SearchAndFilter
  onSearch={setSearchTerm}
  onFilter={setFilters}
  categories={['food', 'transport', 'utilities']}
  placeholder="Search expenses..."
  resultCount={filteredExpenses.length}
  totalCount={expenses.length}
/>
```

### Advanced Usage with All Features
```jsx
<SearchAndFilter
  onSearch={handleSearch}
  onFilter={handleFilter}
  categories={getUniqueCategories(data, 'category')}
  placeholder="Search transactions by title, description, or category..."
  resultCount={filteredData.length}
  totalCount={data.length}
  isLoading={loading}
  suggestions={data.map(item => item.title).filter(unique)}
  onSuggestionSelect={(suggestion) => {
    // Handle suggestion selection
    console.log('Selected:', suggestion);
  }}
  persistFilters={true}
  filterKey="transactions"
  showAmountFilter={true}
/>
```

## Keyboard Shortcuts

- **Ctrl+K / Cmd+K**: Focus search input
- **Escape**: Clear search or close suggestions
- **Arrow Up/Down**: Navigate suggestions
- **Enter**: Select highlighted suggestion
- **Tab**: Select suggestion and move to next element

## Mobile Features

### Touch-Optimized Interface
- Minimum 44px touch targets
- Large, easy-to-tap buttons
- Swipe-friendly modal interface
- Optimized keyboard for number inputs

### Mobile Filter Modal
- Full-screen modal on mobile devices
- Touch-friendly form controls
- Clear visual hierarchy
- Easy dismiss gestures

## Accessibility Features

### ARIA Support
- Proper role attributes (combobox, listbox, option)
- aria-expanded for collapsible sections
- aria-label for all interactive elements
- Screen reader announcements

### Keyboard Navigation
- Full keyboard accessibility
- Focus management
- Logical tab order
- Escape key handling

## Performance Optimizations

### Debouncing
- 300ms search debounce
- Prevents excessive API calls
- Smooth user experience

### Memoization
- useCallback for event handlers
- useMemo for expensive calculations
- Optimized re-renders

### Filter Persistence
- localStorage integration
- Maintains state across sessions
- Unique keys for different contexts

## Styling and Theming

### Design System Integration
- Consistent with app's Tailwind CSS theme
- Dark mode support
- Responsive breakpoints
- Consistent spacing and typography

### Custom Scrollbars
- Styled scrollbars for better aesthetics
- Cross-browser compatibility
- Touch-friendly on mobile

## Loading States

### Skeleton Component
```jsx
import { SearchAndFilterSkeleton } from './components/ui/SearchAndFilter';

{isInitialLoading ? (
  <SearchAndFilterSkeleton />
) : (
  <SearchAndFilter {...props} />
)}
```

### Loading Indicators
- Spinner in search input during loading
- Disabled states for form elements
- Visual feedback for all async operations

## Filter Types Supported

1. **Text Search**: Full-text search across multiple fields
2. **Category Filter**: Dropdown selection
3. **Date Range**: From/to date pickers
4. **Amount Range**: Min/max number inputs
5. **Custom Filters**: Extensible for additional filter types

## Browser Support

- Modern browsers (Chrome, Firefox, Safari, Edge)
- Mobile browsers (iOS Safari, Chrome Mobile)
- Graceful degradation for older browsers
- Progressive enhancement approach

## Best Practices

1. **Always provide resultCount and totalCount** for better UX
2. **Use unique filterKey** when using persistence
3. **Provide meaningful suggestions** for better search experience
4. **Handle loading states** appropriately
5. **Test on mobile devices** for touch interactions
