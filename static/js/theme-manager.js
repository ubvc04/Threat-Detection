// Theme Management System
class ThemeManager {
    constructor() {
        this.themeToggle = document.getElementById('themeToggle');
        this.themeIcon = document.getElementById('themeIcon');
        this.html = document.documentElement;
        
        this.init();
    }
    
    init() {
        // Load saved theme or default to light
        const savedTheme = localStorage.getItem('theme') || 'light';
        this.setTheme(savedTheme);
        
        // Add event listener
        this.themeToggle.addEventListener('click', () => {
            this.toggleTheme();
        });
        
        // Listen for theme changes from other tabs/windows
        window.addEventListener('storage', (e) => {
            if (e.key === 'theme') {
                this.setTheme(e.newValue || 'light');
            }
        });
    }
    
    setTheme(theme) {
        this.html.setAttribute('data-theme', theme);
        this.updateIcon(theme);
        localStorage.setItem('theme', theme);
        
        // Update server-side preference via AJAX
        this.updateServerTheme(theme);
    }
    
    toggleTheme() {
        const currentTheme = this.html.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        this.setTheme(newTheme);
    }
    
    updateIcon(theme) {
        if (theme === 'dark') {
            this.themeIcon.className = 'fas fa-moon';
            this.themeToggle.title = 'Switch to Light Mode';
        } else {
            this.themeIcon.className = 'fas fa-sun';
            this.themeToggle.title = 'Switch to Dark Mode';
        }
    }
    
    updateServerTheme(theme) {
        // Send theme preference to server
        fetch('/dashboard/api/toggle-theme/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': this.getCSRFToken(),
            },
            body: JSON.stringify({ theme: theme })
        }).catch(error => {
            console.log('Theme preference not saved to server:', error);
        });
    }
    
    getCSRFToken() {
        const name = 'csrftoken';
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }
}

// Initialize theme manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new ThemeManager();
});

// Export for use in other scripts
window.ThemeManager = ThemeManager; 