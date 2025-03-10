/**
 * CosmicTeams Loader and Animation System
 * Handles all loading animations and transitions
 */

document.addEventListener('DOMContentLoaded', function() {
    // Create loader overlay and galaxy animation elements
    createLoaderElements();
    
    // Set up event listeners for forms
    setupFormListeners();
    
    // Check if we need to show the entrance animation (after login/registration)
    checkForEntranceAnimation();
    
    // If on main page and no user session, don't show any animations
    preventAnimationsForNonLoggedUsers();
});

/**
 * Creates and adds loader overlay and galaxy animation elements to the DOM
 */
function createLoaderElements() {
    // Create the loader overlay
    const loaderOverlay = document.createElement('div');
    loaderOverlay.className = 'loader-overlay';
    loaderOverlay.innerHTML = `
        <div class="galaxy-loader">
            <div class="galaxy-spiral"></div>
            <div class="galaxy-stars"></div>
            <div class="galaxy-arm"></div>
            <div class="galaxy-arm"></div>
            <div class="galaxy-arm"></div>
            <div class="galaxy-arm"></div>
            <div class="loader-message">Loading...</div>
        </div>
    `;
    document.body.appendChild(loaderOverlay);
    
    // Create 50 stars for the galaxy loader
    const starsContainer = loaderOverlay.querySelector('.galaxy-stars');
    for (let i = 0; i < 50; i++) {
        const star = document.createElement('div');
        star.className = 'star';
        
        // Random star properties
        const size = Math.random() * 2 + 1;
        const posX = Math.random() * 200;
        const posY = Math.random() * 200;
        const delay = Math.random() * 3;
        
        star.style.width = `${size}px`;
        star.style.height = `${size}px`;
        star.style.left = `${posX}px`;
        star.style.top = `${posY}px`;
        star.style.animationDelay = `${delay}s`;
        
        starsContainer.appendChild(star);
    }
    
    // Create the simple circular loader
    const circularLoader = document.createElement('div');
    circularLoader.className = 'circular-loader-overlay';
    circularLoader.innerHTML = `
        <div class="circular-loader">
            <div class="circular-loader-inner"></div>
            <div class="circular-loader-message">Processing...</div>
        </div>
    `;
    document.body.appendChild(circularLoader);
    
    // Create the cosmic entry animation (spaceship)
    const cosmicEntry = document.createElement('div');
    cosmicEntry.className = 'cosmic-entry';
    cosmicEntry.innerHTML = `
        <div class="cosmic-entry-content">
            <div class="space-bg"></div>
            <div class="spaceship">
                <div class="spaceship-body"></div>
                <div class="spaceship-window"></div>
                <div class="spaceship-engines">
                    <div class="engine-flame flame-left"></div>
                    <div class="engine-flame flame-center"></div>
                    <div class="engine-flame flame-right"></div>
                </div>
            </div>
            <div class="cosmic-stars"></div>
            <div class="cosmic-portal"></div>
            <div class="cosmic-message">Entering Cosmic Teams</div>
        </div>
    `;
    document.body.appendChild(cosmicEntry);
    
    // Create stars for cosmic entry
    const cosmicStars = cosmicEntry.querySelector('.cosmic-stars');
    for (let i = 0; i < 150; i++) {
        const star = document.createElement('div');
        star.className = 'cosmic-star';
        
        // Random star properties for 3D effect
        const size = Math.random() * 3 + 1;
        const posX = Math.random() * 100;
        const posY = Math.random() * 100;
        const delay = Math.random() * 3;
        const duration = Math.random() * 2 + 3;
        
        star.style.width = `${size}px`;
        star.style.height = `${size}px`;
        star.style.left = `${posX}%`;
        star.style.top = `${posY}%`;
        star.style.animationDelay = `${delay}s`;
        star.style.animationDuration = `${duration}s`;
        
        cosmicStars.appendChild(star);
    }
}

/**
 * Setup event listeners for forms that need loading animations
 */
function setupFormListeners() {
    // Login form
    const loginForm = document.querySelector('form[action*="login"]');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            // Show the simple circular loader for login
            showCircularLoader('Authenticating...');
            
            // Store a flag in sessionStorage to trigger cosmic entry animation after redirect
            sessionStorage.setItem('showCosmicEntry', 'true');
            
            // Submit the form after a short delay
            setTimeout(() => {
                this.submit();
            }, 1500);
        });
    }
    
    // Registration form
    const registerForm = document.querySelector('form[action*="register"]');
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            e.preventDefault();
            // Show the simple circular loader for registration
            showCircularLoader('Creating your account...');
            
            // Store a flag in sessionStorage to trigger cosmic entry animation after redirect
            sessionStorage.setItem('showCosmicEntry', 'true');
            
            // Submit the form after a short delay
            setTimeout(() => {
                this.submit();
            }, 1500);
        });
    }
    
    // Profile update form
    const profileForm = document.querySelector('form[action*="profile_update"]');
    if (profileForm) {
        profileForm.addEventListener('submit', function(e) {
            e.preventDefault();
            showLoader('Updating your profile...', 3500);
            
            // Submit the form after a delay
            setTimeout(() => {
                this.submit();
            }, 3500);
        });
    }
    
    // Mail compose form
    const mailForm = document.querySelector('form[action*="mail_compose"]');
    if (mailForm) {
        mailForm.addEventListener('submit', function(e) {
            e.preventDefault();
            showLoader('Sending message...', 2500);
            
            // Submit the form after a delay
            setTimeout(() => {
                this.submit();
            }, 2500);
        });
    }
    
    // Password change form
    const passwordForm = document.querySelector('form[action*="change_password"]');
    if (passwordForm) {
        passwordForm.addEventListener('submit', function(e) {
            e.preventDefault();
            showLoader('Updating security settings...', 3000);
            
            // Submit the form after a delay
            setTimeout(() => {
                this.submit();
            }, 3000);
        });
    }
    
    // Team creation/update form
    const teamForm = document.querySelector('form[action*="team"]');
    if (teamForm && (teamForm.action.includes('create') || teamForm.action.includes('edit'))) {
        teamForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const action = teamForm.action.includes('create') ? 'Creating' : 'Updating';
            showLoader(`${action} team...`, 3000);
            
            // Submit the form after a delay
            setTimeout(() => {
                this.submit();
            }, 3000);
        });
    }
}

/**
 * Check if we should show the cosmic entry animation (after login/registration)
 */
function checkForEntranceAnimation() {
    if (sessionStorage.getItem('showCosmicEntry') === 'true') {
        // Clear the flag
        sessionStorage.removeItem('showCosmicEntry');
        
        // Show the cosmic entry animation
        const cosmicEntry = document.querySelector('.cosmic-entry');
        cosmicEntry.classList.add('active');
        
        // After animation is done, remove it
        setTimeout(() => {
            cosmicEntry.classList.add('completed');
            setTimeout(() => {
                cosmicEntry.classList.remove('active');
                cosmicEntry.classList.remove('completed');
            }, 500);
        }, 4000); // Animation lasts exactly 4 seconds as requested
    }
}

/**
 * Prevent animations from showing on main.html for non-logged in users
 */
function preventAnimationsForNonLoggedUsers() {
    // Check if we're on the main page
    const isMainPage = window.location.pathname.includes('main') || 
                        window.location.pathname === '/' || 
                        window.location.pathname.endsWith('/');
    
    // Check if user is logged in (look for profile button or other indicators)
    const userLoggedIn = document.querySelector('.profile-btn') !== null || 
                         document.querySelector('.user-profile') !== null;
    
    if (isMainPage && !userLoggedIn) {
        // Remove any animation flags from session storage
        sessionStorage.removeItem('showCosmicEntry');
        
        // Make sure no animations are shown
        const cosmicEntry = document.querySelector('.cosmic-entry');
        if (cosmicEntry) cosmicEntry.remove();
        
        const loaderOverlay = document.querySelector('.loader-overlay');
        if (loaderOverlay) loaderOverlay.style.display = 'none';
        
        const circularLoader = document.querySelector('.circular-loader-overlay');
        if (circularLoader) circularLoader.style.display = 'none';
    }
}

/**
 * Shows the loader overlay with custom message
 * @param {string} message - Message to display in the loader
 * @param {number} duration - How long to show the loader (ms)
 */
function showLoader(message = 'Loading...', duration = null) {
    const loaderOverlay = document.querySelector('.loader-overlay');
    const loaderMessage = loaderOverlay.querySelector('.loader-message');
    
    // Set the message
    loaderMessage.textContent = message;
    
    // Show the loader
    loaderOverlay.classList.add('active');
    
    // If duration is provided, hide the loader after that time
    if (duration) {
        setTimeout(() => {
            hideLoader();
        }, duration);
    }
}

/**
 * Shows a simple circular loader for login/register
 * @param {string} message - Message to display in the loader
 */
function showCircularLoader(message = 'Processing...') {
    const circularLoader = document.querySelector('.circular-loader-overlay');
    const loaderMessage = circularLoader.querySelector('.circular-loader-message');
    
    // Set the message
    loaderMessage.textContent = message;
    
    // Show the loader
    circularLoader.classList.add('active');
}

/**
 * Hides all loaders
 */
function hideLoader() {
    const loaderOverlay = document.querySelector('.loader-overlay');
    loaderOverlay.classList.remove('active');
    
    const circularLoader = document.querySelector('.circular-loader-overlay');
    circularLoader.classList.remove('active');
}

/**
 * Shows a toast message for success or error notifications
 * @param {string} message - Message to display
 * @param {string} type - 'success' or 'error'
 */
function showToast(message, type = 'success') {
    // Remove any existing toast
    const existingToast = document.querySelector('.action-message');
    if (existingToast) {
        existingToast.remove();
    }
    
    // Create a new toast
    const toast = document.createElement('div');
    toast.className = `action-message ${type}`;
    
    // Set the icon based on type
    const icon = type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle';
    
    toast.innerHTML = `<i class="fas ${icon}"></i> ${message}`;
    document.body.appendChild(toast);
    
    // Show the toast
    setTimeout(() => {
        toast.classList.add('active');
    }, 10);
    
    // Hide the toast after 4 seconds
    setTimeout(() => {
        toast.classList.remove('active');
        
        // Remove from DOM after animation completes
        setTimeout(() => {
            toast.remove();
        }, 400);
    }, 4000);
}

// Export functions for global use
window.cosmicLoaders = {
    showLoader,
    hideLoader,
    showCircularLoader,
    showToast
}; 