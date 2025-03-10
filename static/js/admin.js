// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // User search functionality
    const userSearchInput = document.getElementById('user-search');
    if (userSearchInput) {
        userSearchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const userRows = document.querySelectorAll('.users-table tbody tr');
            
            userRows.forEach(row => {
                const username = row.querySelector('td:nth-child(2)').textContent.toLowerCase();
                const email = row.querySelector('td:nth-child(3)').textContent.toLowerCase();
                const fullName = row.querySelector('td:nth-child(4)').textContent.toLowerCase();
                
                if (username.includes(searchTerm) || email.includes(searchTerm) || fullName.includes(searchTerm)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    }
    
    // Delete user confirmation
    const deleteForms = document.querySelectorAll('.delete-form');
    deleteForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const confirmed = confirm('Are you sure you want to delete this user? This action cannot be undone.');
            if (!confirmed) {
                e.preventDefault();
            }
        });
    });
    
    // Toggle admin status confirmation
    const adminForms = document.querySelectorAll('form[action*="toggle-admin"]');
    adminForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const isAdmin = this.querySelector('.admin-btn i').classList.contains('fa-user-minus');
            const action = isAdmin ? 'remove admin privileges from' : 'make';
            const confirmed = confirm(`Are you sure you want to ${action} this user an admin?`);
            if (!confirmed) {
                e.preventDefault();
            }
        });
    });
    
    // Add animation to stats
    const statValues = document.querySelectorAll('.stat-value');
    statValues.forEach((stat, index) => {
        stat.style.opacity = '0';
        stat.style.transform = 'translateY(10px)';
        
        setTimeout(() => {
            stat.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            stat.style.opacity = '1';
            stat.style.transform = 'translateY(0)';
        }, 100 * index);
    });
}); 