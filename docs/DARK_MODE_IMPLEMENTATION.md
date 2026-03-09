# Dark Mode Implementation

## Overview
This document describes the implementation of dark and light mode theming for this Flask web application.

## Changes Made

### 1. CSS Variables Refactoring (`web_static/styles.css`)
- **Added comprehensive CSS variable system** with two themes:
  - `:root` - Light mode (default)
  - `[data-theme="dark"]` - Dark mode
  
- **Variable categories**:
  - Primary colors (brand colors)
  - Success colors (green tones)
  - Error/Danger colors (red tones)
  - Info colors (blue tones)
  - Warning colors (orange tones)
  - Background colors (surfaces)
  - Text colors (typography)
  - Border colors
  - Shadow colors
  - Badge colors
  - Link colors
  - Google button colors
  - Miscellaneous colors

- **All hardcoded colors replaced** with CSS variables throughout the entire stylesheet, ensuring consistent theming across:
  - Forms and inputs
  - Buttons (primary, secondary, add, icon, danger)
  - Cards and tiles
  - Tables (data tables, standard tables)
  - Messages (error, success, info, warning)
  - Badges
  - Links
  - Filters
  - Lists
  - Dividers
  - Modals

### 2. Theme Toggle Implementation (JavaScript)
To enable dark mode toggling in your Flask application, add the following JavaScript to your templates:

**Features**:
- Persists theme preference to `localStorage` (key: `abnemo-theme`)
- Detects and respects system/browser theme preference using `prefers-color-scheme` media query
- Defaults to light mode if no preference is set
- Applies theme by setting `data-theme` attribute on document root element

**Example Implementation**:
```javascript
// Theme management
function initTheme() {
  const savedTheme = localStorage.getItem('abnemo-theme');
  const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const theme = savedTheme || (systemPrefersDark ? 'dark' : 'light');
  applyTheme(theme);
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('abnemo-theme', theme);
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
  const newTheme = currentTheme === 'light' ? 'dark' : 'light';
  applyTheme(newTheme);
}

// Initialize theme on page load
document.addEventListener('DOMContentLoaded', initTheme);
```

### 3. Adding Theme Toggle Button
Add a theme toggle button to your header/navigation:

**HTML Example**:
```html
<button onclick="toggleTheme()" aria-label="Toggle theme" title="Toggle dark/light mode">
  🌙/☀️
</button>
```

**Styled Button Example**:
```html
<button class="btn-icon" onclick="toggleTheme()" aria-label="Toggle theme">
  <span id="theme-icon">🌙</span>
</button>
```

With JavaScript to update the icon:
```javascript
function updateThemeIcon() {
  const theme = document.documentElement.getAttribute('data-theme') || 'light';
  const icon = document.getElementById('theme-icon');
  if (icon) {
    icon.textContent = theme === 'light' ? '🌙' : '☀️';
  }
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
  const newTheme = currentTheme === 'light' ? 'dark' : 'light';
  applyTheme(newTheme);
  updateThemeIcon();
}
```

## How It Works

1. **On Application Load**:
   - JavaScript checks localStorage for saved preference
   - If no saved preference, checks system/browser preference
   - Falls back to light mode if neither exists
   - Applies the determined theme to the document root

2. **User Interaction**:
   - User clicks the theme toggle button
   - `toggleTheme()` function is called
   - Theme is toggled between 'light' and 'dark'
   - `data-theme` attribute is updated on document root
   - Preference is saved to localStorage
   - CSS variables automatically update based on `data-theme` attribute
   - All UI elements using CSS variables instantly reflect the new theme

3. **Theme Persistence**:
   - Theme choice is saved to localStorage
   - Persists across browser sessions
   - User's preference is remembered

## Browser Compatibility
- Modern browsers with CSS custom properties support
- `prefers-color-scheme` media query support for system theme detection
- localStorage support for persistence

## Accessibility
- Theme toggle button should include proper ARIA labels
- Use tooltips to describe the action (e.g., "Toggle dark/light mode")
- Icon should change to indicate current mode

## Template Guidelines
All Flask templates should use global styles from `styles.css` instead of inline styles to ensure:
- Consistent theming across the application
- Automatic dark mode support
- Reduced CSS duplication
- Easier maintenance

**Example**: Use classes like `.container`, `.card`, `.btn-primary`, `.error-box`, etc. from the global stylesheet.

## Integration with Flask Templates
1. Link the CSS file in your base template:
```html
<link rel="stylesheet" href="{{ url_for('static', filename='styles.css') }}">
```

2. Add the theme initialization script to your base template
3. Add a theme toggle button to your navigation/header
4. Use CSS variable-based classes throughout your templates

## Future Enhancements (Optional)
- Add smooth transition animations between themes
- Add more theme variants (e.g., high contrast, blue theme)
- Add theme preview in settings
- Sync theme across multiple tabs using storage events
- Add theme selection dropdown (light/dark/auto)
