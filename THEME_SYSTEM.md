# 🌓 Dark/Light Theme System

## Overview
The Threat Detection System now includes a comprehensive dark/light theme system that works across all pages and persists user preferences.

## Features

### ✅ **Complete Theme Coverage**
- **Light Mode**: Clean, bright interface with light backgrounds
- **Dark Mode**: Eye-friendly dark interface with proper contrast
- **All Components**: Cards, tables, forms, modals, dropdowns, and more

### ✅ **User Experience**
- **Toggle Button**: Sun/Moon icon in the navigation bar
- **Smooth Transitions**: 0.3s transitions for all color changes
- **Persistent Preferences**: Theme choice saved in browser localStorage
- **Cross-Tab Sync**: Theme changes sync across browser tabs/windows

### ✅ **Server Integration**
- **Session Storage**: Theme preference saved in Django sessions
- **API Endpoint**: `/dashboard/api/toggle-theme/` for server-side updates
- **CSRF Protection**: Secure theme updates with CSRF tokens

## Color Schemes

### Light Mode
- **Primary Background**: `#ffffff` (White)
- **Secondary Background**: `#f8f9fa` (Light Gray)
- **Card Background**: `#ffffff` (White)
- **Text Primary**: `#2c3e50` (Dark Blue-Gray)
- **Text Secondary**: `#6c757d` (Medium Gray)
- **Borders**: `#dee2e6` (Light Gray)

### Dark Mode
- **Primary Background**: `#0f0f23` (Very Dark Blue)
- **Secondary Background**: `#1a1a2e` (Dark Blue)
- **Card Background**: `#16213e` (Medium Dark Blue)
- **Text Primary**: `#ffffff` (White)
- **Text Secondary**: `#b8b8b8` (Light Gray)
- **Borders**: `#2d3748` (Dark Gray)

## Implementation Details

### CSS Variables
All colors are defined using CSS custom properties (variables) in `static/css/themes.css`:
```css
:root {
    --bg-primary: #ffffff;
    --text-primary: #2c3e50;
    /* ... more variables */
}

[data-theme="dark"] {
    --bg-primary: #0f0f23;
    --text-primary: #ffffff;
    /* ... dark mode variables */
}
```

### JavaScript Management
Theme switching is handled by `static/js/theme-manager.js`:
- **LocalStorage**: Client-side preference storage
- **DOM Updates**: Dynamic theme application
- **Server Sync**: AJAX updates to Django sessions
- **Cross-Tab**: Storage event listeners for synchronization

### Django Integration
- **Session Storage**: Server-side preference tracking
- **Context Variables**: Theme passed to all templates
- **API Endpoint**: RESTful theme toggle endpoint

## Usage

### For Users
1. **Toggle Theme**: Click the sun/moon icon in the navigation bar
2. **Automatic Persistence**: Your choice is remembered across sessions
3. **Cross-Tab Sync**: Changes apply to all open tabs

### For Developers
1. **Add Theme Support**: Use CSS variables for colors
2. **Template Integration**: Include `{% load static %}` and theme CSS/JS
3. **Custom Components**: Follow the variable naming convention

## File Structure
```
static/
├── css/
│   └── themes.css          # Theme variables and styles
└── js/
    └── theme-manager.js    # Theme switching logic

templates/
└── base.html              # Main template with theme toggle

dashboard/
├── views.py               # Theme API endpoint
└── urls.py               # Theme toggle route
```

## Browser Support
- ✅ **Modern Browsers**: Full support for CSS variables and localStorage
- ✅ **Smooth Transitions**: CSS transitions for all modern browsers
- ✅ **Fallback**: Graceful degradation for older browsers

## Performance
- **Lightweight**: Minimal CSS and JavaScript overhead
- **Efficient**: CSS variables for instant theme switching
- **Optimized**: No page reloads required for theme changes 