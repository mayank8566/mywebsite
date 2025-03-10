// Galaxy Theme JavaScript

// DOM elements
const userProfile = document.querySelector('.user-profile');

// Add hover effect for team cards
function addTeamCardEffects() {
    const teamCards = document.querySelectorAll('.team-card');
    
    teamCards.forEach(card => {
        // Add mousemove event for "follow" effect of glow
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            // Update the position of the glow effect
            const glow = card.querySelector('.card-glow');
            if (glow) {
                glow.style.background = `radial-gradient(circle at ${x}px ${y}px, rgba(138, 43, 226, 0.4) 0%, rgba(20, 20, 45, 0) 70%)`;
                glow.style.opacity = '1';
            }
        });
        
        // Reset on mouseout
        card.addEventListener('mouseleave', () => {
            const glow = card.querySelector('.card-glow');
            if (glow) {
                glow.style.opacity = '0';
            }
        });
    });
}

// Initialize all effects
function initGalaxyEffects() {
    addTeamCardEffects();
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    initGalaxyEffects();
    
    // Initialize dropdown functionality
    const dropdownToggle = document.querySelector('.profile-btn');
    const dropdownMenu = document.querySelector('.dropdown-menu');
    
    if (dropdownToggle && dropdownMenu) {
        dropdownToggle.addEventListener('click', (e) => {
            e.preventDefault();
            dropdownMenu.classList.toggle('active');
        });
        
        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!dropdownToggle.contains(e.target) && !dropdownMenu.contains(e.target)) {
                dropdownMenu.classList.remove('active');
            }
        });
    }
    
    // Convert standard alerts to animated popups
    convertAlertsToPopups();
    
    // Check if user is banned and show ban popup
    checkForBannedStatus();
});

// Function to convert standard alerts to animated popups
function convertAlertsToPopups() {
    // Get all alert elements
    const alerts = document.querySelectorAll('.alert');
    
    // Remove old alerts container if it exists
    const oldAlertContainer = document.getElementById('alert-popup-container');
    if (oldAlertContainer) {
        oldAlertContainer.remove();
    }
    
    // Create container for alerts if there are any
    if (alerts.length > 0) {
        const alertContainer = document.createElement('div');
        alertContainer.id = 'alert-popup-container';
        document.body.appendChild(alertContainer);
        
        // Process each alert
        alerts.forEach((alert, index) => {
            // Get alert data
            let category = 'info';
            if (alert.classList.contains('success')) category = 'success';
            if (alert.classList.contains('error')) category = 'error';
            if (alert.classList.contains('warning')) category = 'warning';
            
            const message = alert.textContent.trim();
            
            // Create popup element
            const popup = document.createElement('div');
            popup.className = `alert-popup ${category}`;
            popup.style.animationDelay = `${index * 0.2}s, ${4.5 + index * 0.2}s`;
            
            // Set icon based on category
            let icon = 'info-circle';
            if (category === 'success') icon = 'check-circle';
            if (category === 'error') icon = 'exclamation-circle';
            if (category === 'warning') icon = 'exclamation-triangle';
            
            // Populate popup
            popup.innerHTML = `
                <div class="alert-popup-content">
                    <div class="alert-popup-icon">
                        <i class="fas fa-${icon}"></i>
                    </div>
                    <div class="alert-popup-message">${message}</div>
                    <div class="alert-popup-close">
                        <i class="fas fa-times"></i>
                    </div>
                </div>
            `;
            
            // Add popup to container
            alertContainer.appendChild(popup);
            
            // Add close functionality
            const closeBtn = popup.querySelector('.alert-popup-close');
            closeBtn.addEventListener('click', () => {
                popup.style.animation = 'fadeOut 0.5s forwards';
                setTimeout(() => {
                    popup.remove();
                }, 500);
            });
            
            // Remove original alert
            alert.remove();
            
            // Remove popup after animation completes
            setTimeout(() => {
                popup.remove();
            }, 5000 + (index * 200));
        });
    }
}

// Function to check if user is banned and show ban popup
function checkForBannedStatus() {
    // Check if ban message exists in URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const isBanned = urlParams.get('banned');
    const banReason = urlParams.get('reason') || 'Your account has been banned for violating our community guidelines.';
    
    if (isBanned === 'true') {
        showBanPopup(banReason);
    }
}

// Function to display ban popup
function showBanPopup(message) {
    // Create ban popup
    const banPopup = document.createElement('div');
    banPopup.className = 'ban-popup';
    
    banPopup.innerHTML = `
        <div class="ban-popup-content">
            <div class="ban-popup-icon">
                <i class="fas fa-ban"></i>
            </div>
            <h2 class="ban-popup-title">Account Banned</h2>
            <p class="ban-popup-message">${message}</p>
            <button class="ban-popup-button">Logout</button>
        </div>
    `;
    
    // Add to body
    document.body.appendChild(banPopup);
    
    // Add button functionality
    const logoutBtn = banPopup.querySelector('.ban-popup-button');
    logoutBtn.addEventListener('click', () => {
        window.location.href = '/logout';
    });
}

// Function to show a manual popup alert
function showPopupAlert(message, category = 'info') {
    const alertContainer = document.getElementById('alert-popup-container') || (() => {
        const container = document.createElement('div');
        container.id = 'alert-popup-container';
        document.body.appendChild(container);
        return container;
    })();
    
    // Set icon based on category
    let icon = 'info-circle';
    if (category === 'success') icon = 'check-circle';
    if (category === 'error') icon = 'exclamation-circle';
    if (category === 'warning') icon = 'exclamation-triangle';
    
    // Create popup
    const popup = document.createElement('div');
    popup.className = `alert-popup ${category}`;
    
    popup.innerHTML = `
        <div class="alert-popup-content">
            <div class="alert-popup-icon">
                <i class="fas fa-${icon}"></i>
            </div>
            <div class="alert-popup-message">${message}</div>
            <div class="alert-popup-close">
                <i class="fas fa-times"></i>
            </div>
        </div>
    `;
    
    // Add to container
    alertContainer.appendChild(popup);
    
    // Add close functionality
    const closeBtn = popup.querySelector('.alert-popup-close');
    closeBtn.addEventListener('click', () => {
        popup.style.animation = 'fadeOut 0.5s forwards';
        setTimeout(() => {
            popup.remove();
        }, 500);
    });
    
    // Remove after animation
    setTimeout(() => {
        popup.style.animation = 'fadeOut 0.5s forwards';
        setTimeout(() => {
            popup.remove();
        }, 500);
    }, 5000);
} 