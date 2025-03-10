// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Get DOM elements
    const container = document.getElementById('container');
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const registerLink = document.getElementById('register-link');
    const loginLink = document.getElementById('login-link');
    const registerBtn = document.getElementById('register-btn');
    const loginBtn = document.getElementById('login-btn');
    const togglePasswordBtns = document.querySelectorAll('.toggle-password');
    
    // Toggle between login and register forms
    if (registerLink) {
        registerLink.addEventListener('click', function(e) {
            e.preventDefault();
            container.classList.add('sign-up-mode');
            loginForm.classList.remove('active');
            registerForm.classList.add('active');
        });
    }
    
    if (loginLink) {
        loginLink.addEventListener('click', function(e) {
            e.preventDefault();
            container.classList.remove('sign-up-mode');
            registerForm.classList.remove('active');
            loginForm.classList.add('active');
        });
    }
    
    if (registerBtn) {
        registerBtn.addEventListener('click', function() {
            container.classList.add('sign-up-mode');
            loginForm.classList.remove('active');
            registerForm.classList.add('active');
        });
    }
    
    if (loginBtn) {
        loginBtn.addEventListener('click', function() {
            container.classList.remove('sign-up-mode');
            registerForm.classList.remove('active');
            loginForm.classList.add('active');
        });
    }
    
    // Toggle password visibility
    togglePasswordBtns.forEach(function(btn) {
        btn.addEventListener('click', function() {
            const input = this.previousElementSibling;
            const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
            input.setAttribute('type', type);
            this.querySelector('i').classList.toggle('fa-eye');
            this.querySelector('i').classList.toggle('fa-eye-slash');
        });
    });
    
    // Form validation
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            // Don't prevent default form submission
            // Let the browser handle it normally
            
            // Get form inputs
            const username = this.querySelector('input[name="username"]').value.trim();
            const password = this.querySelector('input[name="password"]').value.trim();
            
            // Simple validation
            if (username === '' || password === '') {
                e.preventDefault(); // Only prevent if validation fails
                showMessage(this, 'Please fill in all fields', 'error');
                this.classList.add('shake');
                setTimeout(() => {
                    this.classList.remove('shake');
                }, 600);
                return;
            }
        });
    }
    
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            // Don't prevent default form submission
            // Let the browser handle it normally
            
            // Get form inputs
            const username = this.querySelector('input[name="username"]').value.trim();
            const email = this.querySelector('input[name="email"]').value.trim();
            const password = this.querySelector('input[name="password"]').value.trim();
            const confirmPassword = this.querySelector('input[name="confirm_password"]').value.trim();
            const termsChecked = this.querySelector('input[name="terms"]').checked;
            
            // Simple validation
            if (username === '' || email === '' || password === '' || confirmPassword === '') {
                e.preventDefault(); // Only prevent if validation fails
                showMessage(this, 'Please fill in all fields', 'error');
                this.classList.add('shake');
                setTimeout(() => {
                    this.classList.remove('shake');
                }, 600);
                return;
            }
            
            // Email validation
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                e.preventDefault();
                showMessage(this, 'Please enter a valid email address', 'error');
                return;
            }
            
            // Password validation
            if (password.length < 6) {
                e.preventDefault();
                showMessage(this, 'Password must be at least 6 characters long', 'error');
                return;
            }
            
            // Confirm password
            if (password !== confirmPassword) {
                e.preventDefault();
                showMessage(this, 'Passwords do not match', 'error');
                return;
            }
            
            // Terms and conditions
            if (!termsChecked) {
                e.preventDefault();
                showMessage(this, 'Please agree to the Terms & Conditions', 'error');
                return;
            }
        });
    }
    
    // Function to show error or success messages
    function showMessage(form, message, type) {
        // Remove any existing messages
        const existingMessage = form.querySelector('.message');
        if (existingMessage) {
            existingMessage.remove();
        }
        
        // Create new message element
        const messageElement = document.createElement('div');
        messageElement.className = `message ${type}-message`;
        messageElement.textContent = message;
        
        // Insert at the top of the form
        form.insertBefore(messageElement, form.firstChild);
        
        // Remove message after 5 seconds if it's an error
        if (type === 'error') {
            setTimeout(() => {
                messageElement.remove();
            }, 5000);
        }
    }
    
    // Add placeholder SVG images if real images are not available
    const images = document.querySelectorAll('.image');
    images.forEach(img => {
        if (!img.complete || img.naturalHeight === 0) {
            img.src = createPlaceholderSVG(img.alt);
        }
    });
    
    // Function to create placeholder SVG for missing images
    function createPlaceholderSVG(alt) {
        const isLogin = alt.includes('Login');
        const color = isLogin ? '#4a6cf7' : '#6a11cb';
        
        return `data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 300 300'%3e%3crect width='300' height='300' fill='%23f8f9fa'/%3e%3cpath d='M150,50 C180,50 205,75 205,105 C205,135 180,160 150,160 C120,160 95,135 95,105 C95,75 120,50 150,50 Z M60,250 L240,250 C240,190 195,170 150,170 C105,170 60,190 60,250 Z' fill='${color}' opacity='0.5'/%3e%3c/svg%3e`;
    }
}); 