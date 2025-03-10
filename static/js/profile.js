// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Profile menu navigation
    const profileMenuLinks = document.querySelectorAll('.profile-menu a');
    const profileSections = document.querySelectorAll('.profile-section');
    
    // Hide all sections except the first one
    profileSections.forEach((section, index) => {
        if (index !== 0) {
            section.style.display = 'none';
        }
    });
    
    // Add click event to menu links
    profileMenuLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            if (this.getAttribute('href').startsWith('#')) {
                e.preventDefault();
                
                // Remove active class from all links
                profileMenuLinks.forEach(item => {
                    item.classList.remove('active');
                });
                
                // Add active class to clicked link
                this.classList.add('active');
                
                // Get the target section
                const targetId = this.getAttribute('href').substring(1);
                
                // Hide all sections
                profileSections.forEach(section => {
                    section.style.display = 'none';
                });
                
                // Show the target section
                document.getElementById(targetId).style.display = 'block';
                
                // Smooth scroll to top of content on mobile
                if (window.innerWidth < 992) {
                    document.querySelector('.profile-content').scrollIntoView({
                        behavior: 'smooth'
                    });
                }
            }
        });
    });
    
    // Password confirmation validation
    const newPasswordInput = document.getElementById('new_password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    
    if (newPasswordInput && confirmPasswordInput) {
        confirmPasswordInput.addEventListener('input', function() {
            if (this.value !== newPasswordInput.value) {
                this.setCustomValidity('Passwords do not match');
            } else {
                this.setCustomValidity('');
            }
        });
        
        newPasswordInput.addEventListener('input', function() {
            if (confirmPasswordInput.value !== '') {
                if (confirmPasswordInput.value !== this.value) {
                    confirmPasswordInput.setCustomValidity('Passwords do not match');
                } else {
                    confirmPasswordInput.setCustomValidity('');
                }
            }
        });
    }
    
    // Profile picture upload and preview
    const profilePicUpload = document.getElementById('profile-pic-upload');
    const profilePicInput = document.getElementById('profile_pic');
    const avatarImage = document.querySelector('.avatar-image');
    
    // Connect the hidden file input with the visible button
    if (profilePicUpload) {
        profilePicUpload.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                // Transfer the selected file to the form input
                const dataTransfer = new DataTransfer();
                dataTransfer.items.add(this.files[0]);
                profilePicInput.files = dataTransfer.files;
                
                // Trigger the preview
                handleProfilePicPreview(this.files[0]);
            }
        });
    }
    
    // Handle profile picture preview when selected through the form
    if (profilePicInput) {
        profilePicInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                handleProfilePicPreview(this.files[0]);
            }
        });
    }
    
    // Function to handle profile picture preview
    function handleProfilePicPreview(file) {
        // Check if file is an image
        if (!file.type.match('image.*')) {
            showNotification('Please select an image file', 'error');
            return;
        }
        
        // Check file size (max 5MB)
        if (file.size > 5 * 1024 * 1024) {
            showNotification('Image size should be less than 5MB', 'error');
            return;
        }
        
        // Create a preview
        const reader = new FileReader();
        reader.onload = function(e) {
            // Remove existing content
            avatarImage.innerHTML = '';
            
            // Create image element
            const img = document.createElement('img');
            img.src = e.target.result;
            img.alt = 'Profile picture preview';
            avatarImage.appendChild(img);
            
            showNotification('Profile picture selected. Save changes to update.', 'info');
        };
        reader.readAsDataURL(file);
    }
    
    // Danger zone buttons
    const deactivateBtn = document.getElementById('deactivate-btn');
    const deleteBtn = document.getElementById('delete-btn');
    
    if (deactivateBtn) {
        deactivateBtn.addEventListener('click', function() {
            if (confirm('Are you sure you want to deactivate your account? You can reactivate it later.')) {
                showNotification('Account deactivation feature coming soon!', 'info');
            }
        });
    }
    
    if (deleteBtn) {
        deleteBtn.addEventListener('click', function() {
            if (confirm('Are you sure you want to delete your account? This action cannot be undone!')) {
                if (confirm('All your data will be permanently deleted. This action CANNOT be undone. Are you REALLY sure?')) {
                    showNotification('Account deletion feature coming soon!', 'info');
                }
            }
        });
    }
    
    // Function to show notifications
    function showNotification(message, type = 'info') {
        // Check if notification container exists, if not create it
        let notificationContainer = document.querySelector('.notification-container');
        
        if (!notificationContainer) {
            notificationContainer = document.createElement('div');
            notificationContainer.className = 'notification-container';
            document.body.appendChild(notificationContainer);
            
            // Add styles for the notification container
            const style = document.createElement('style');
            style.textContent = `
                .notification-container {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    z-index: 1000;
                }
                
                .notification {
                    background-color: var(--light-color);
                    color: var(--text-color);
                    border-radius: var(--border-radius);
                    box-shadow: var(--box-shadow);
                    padding: 1rem 1.5rem;
                    margin-bottom: 1rem;
                    display: flex;
                    align-items: center;
                    gap: 0.8rem;
                    transform: translateX(100%);
                    opacity: 0;
                    transition: transform 0.3s ease, opacity 0.3s ease;
                    max-width: 350px;
                }
                
                .notification.show {
                    transform: translateX(0);
                    opacity: 1;
                }
                
                .notification.success {
                    border-left: 4px solid var(--success-color);
                }
                
                .notification.error {
                    border-left: 4px solid var(--danger-color);
                }
                
                .notification.info {
                    border-left: 4px solid var(--info-color);
                }
                
                .notification.warning {
                    border-left: 4px solid var(--warning-color);
                }
                
                .notification-icon {
                    font-size: 1.5rem;
                }
                
                .notification.success .notification-icon {
                    color: var(--success-color);
                }
                
                .notification.error .notification-icon {
                    color: var(--danger-color);
                }
                
                .notification.info .notification-icon {
                    color: var(--info-color);
                }
                
                .notification.warning .notification-icon {
                    color: var(--warning-color);
                }
                
                .notification-content {
                    flex: 1;
                }
                
                .notification-close {
                    cursor: pointer;
                    font-size: 1.2rem;
                    color: var(--secondary-color);
                    transition: var(--transition);
                }
                
                .notification-close:hover {
                    color: var(--text-color);
                }
            `;
            
            document.head.appendChild(style);
        }
        
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        
        // Set icon based on notification type
        let icon;
        switch (type) {
            case 'success':
                icon = 'fa-check-circle';
                break;
            case 'error':
                icon = 'fa-exclamation-circle';
                break;
            case 'warning':
                icon = 'fa-exclamation-triangle';
                break;
            default:
                icon = 'fa-info-circle';
        }
        
        notification.innerHTML = `
            <div class="notification-icon">
                <i class="fas ${icon}"></i>
            </div>
            <div class="notification-content">
                ${message}
            </div>
            <div class="notification-close">
                <i class="fas fa-times"></i>
            </div>
        `;
        
        // Add notification to container
        notificationContainer.appendChild(notification);
        
        // Show notification
        setTimeout(() => {
            notification.classList.add('show');
        }, 10);
        
        // Add click event to close button
        notification.querySelector('.notification-close').addEventListener('click', function() {
            closeNotification(notification);
        });
        
        // Auto close after 5 seconds
        setTimeout(() => {
            closeNotification(notification);
        }, 5000);
    }
    
    // Function to close notification
    function closeNotification(notification) {
        notification.classList.remove('show');
        
        // Remove from DOM after transition
        setTimeout(() => {
            notification.remove();
        }, 300);
    }
    
    // Form submission handling
    const profileForm = document.querySelector('.profile-form');
    
    if (profileForm) {
        profileForm.addEventListener('submit', function(e) {
            // In a real application, you would submit the form to the server
            // For now, we'll just show a notification
            if (this.id !== 'password-form') {
                // Don't prevent default, let the form submit normally
                // e.preventDefault();
                // showNotification('Profile updated successfully!', 'success');
            }
        });
    }
}); 