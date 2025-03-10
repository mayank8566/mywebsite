// Galaxy Auth JavaScript

// DOM elements
const container = document.querySelector('.container');
const registerBtn = document.getElementById('register-btn');
const loginBtn = document.getElementById('login-btn');
const registerLink = document.getElementById('register-link');
const loginLink = document.getElementById('login-link');
const togglePasswordBtns = document.querySelectorAll('.toggle-password');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const starsContainer = document.getElementById('stars-container');

// Create stars for background
function createStars() {
    const starCount = Math.floor(window.innerWidth * window.innerHeight / 1000);
    
    for (let i = 0; i < starCount; i++) {
        const star = document.createElement('div');
        star.className = 'star';
        
        // Random position
        const x = Math.random() * window.innerWidth;
        const y = Math.random() * window.innerHeight;
        
        // Random size (smaller stars are more common)
        const size = Math.random() * 3;
        
        // Random opacity for twinkling effect
        const opacity = Math.random() * 0.8 + 0.2;
        
        // Random delay for twinkling
        const delay = Math.random() * 10;
        
        // Random duration for twinkling
        const duration = Math.random() * 3 + 2;
        
        // Apply styles
        star.style.width = `${size}px`;
        star.style.height = `${size}px`;
        star.style.left = `${x}px`;
        star.style.top = `${y}px`;
        star.style.opacity = opacity;
        star.style.animationDelay = `${delay}s`;
        star.style.animationDuration = `${duration}s`;
        
        // Add to container
        starsContainer.appendChild(star);
    }
}

// Initialize stars
createStars();

// Form switch event listeners
if (registerBtn) {
    registerBtn.addEventListener('click', () => {
        container.classList.add('register-active');
        playTransitionSound();
    });
}

if (loginBtn) {
    loginBtn.addEventListener('click', () => {
        container.classList.remove('register-active');
        playTransitionSound();
    });
}

if (registerLink) {
    registerLink.addEventListener('click', (e) => {
        e.preventDefault();
        container.classList.add('register-active');
        playTransitionSound();
    });
}

if (loginLink) {
    loginLink.addEventListener('click', (e) => {
        e.preventDefault();
        container.classList.remove('register-active');
        playTransitionSound();
    });
}

// Toggle password visibility
togglePasswordBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        const input = btn.parentElement.querySelector('input');
        const icon = btn.querySelector('i');
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.className = 'fas fa-eye-slash';
        } else {
            input.type = 'password';
            icon.className = 'fas fa-eye';
        }
        
        // Add subtle glow effect when toggling
        btn.style.textShadow = '0 0 10px rgba(147, 112, 219, 0.8)';
        setTimeout(() => {
            btn.style.textShadow = 'none';
        }, 300);
    });
});

// Form validation and animation
function validateForm(form) {
    let isValid = true;
    const inputs = form.querySelectorAll('input[required]');
    
    inputs.forEach(input => {
        if (!input.value.trim()) {
            isValid = false;
            highlightInput(input);
        } else {
            resetInput(input);
        }
    });
    
    // If it's the register form, check if passwords match
    if (form.id === 'register-form') {
        const password = form.querySelector('input[name="password"]');
        const confirmPassword = form.querySelector('input[name="confirm_password"]');
        
        if (password.value !== confirmPassword.value) {
            isValid = false;
            highlightInput(confirmPassword);
            displayErrorMessage('Passwords do not match', form);
        }
    }
    
    if (!isValid) {
        shakeForm(form);
    }
    
    return isValid;
}

function highlightInput(input) {
    input.style.borderColor = '#ff6b6b';
    input.style.boxShadow = '0 0 0 2px rgba(255, 107, 107, 0.3)';
}

function resetInput(input) {
    input.style.borderColor = 'rgba(138, 43, 226, 0.3)';
    input.style.boxShadow = '';
}

function displayErrorMessage(message, form) {
    // Remove any existing error messages
    const existingMessage = form.querySelector('.error-message');
    if (existingMessage) {
        existingMessage.remove();
    }
    
    // Create new error message
    const errorMessage = document.createElement('div');
    errorMessage.className = 'message error-message';
    errorMessage.textContent = message;
    
    // Insert after form title
    const subtitle = form.querySelector('.subtitle');
    subtitle.insertAdjacentElement('afterend', errorMessage);
    
    // Fade out after 5 seconds
    setTimeout(() => {
        errorMessage.style.opacity = '0';
        setTimeout(() => {
            errorMessage.remove();
        }, 500);
    }, 5000);
}

function shakeForm(form) {
    form.classList.add('shake');
    setTimeout(() => {
        form.classList.remove('shake');
    }, 500);
    playErrorSound();
}

// Sound effects (using Web Audio API)
let audioContext;

function initAudio() {
    try {
        audioContext = new (window.AudioContext || window.webkitAudioContext)();
    } catch (e) {
        console.warn('Web Audio API not supported');
    }
}

function playTransitionSound() {
    if (!audioContext) initAudio();
    if (!audioContext) return;
    
    const oscillator = audioContext.createOscillator();
    const gainNode = audioContext.createGain();
    
    oscillator.type = 'sine';
    oscillator.frequency.setValueAtTime(500, audioContext.currentTime);
    oscillator.frequency.exponentialRampToValueAtTime(900, audioContext.currentTime + 0.2);
    
    gainNode.gain.setValueAtTime(0, audioContext.currentTime);
    gainNode.gain.linearRampToValueAtTime(0.1, audioContext.currentTime + 0.05);
    gainNode.gain.linearRampToValueAtTime(0, audioContext.currentTime + 0.3);
    
    oscillator.connect(gainNode);
    gainNode.connect(audioContext.destination);
    
    oscillator.start();
    oscillator.stop(audioContext.currentTime + 0.3);
}

function playErrorSound() {
    if (!audioContext) initAudio();
    if (!audioContext) return;
    
    const oscillator = audioContext.createOscillator();
    const gainNode = audioContext.createGain();
    
    oscillator.type = 'sawtooth';
    oscillator.frequency.setValueAtTime(200, audioContext.currentTime);
    oscillator.frequency.exponentialRampToValueAtTime(100, audioContext.currentTime + 0.3);
    
    gainNode.gain.setValueAtTime(0, audioContext.currentTime);
    gainNode.gain.linearRampToValueAtTime(0.1, audioContext.currentTime + 0.05);
    gainNode.gain.linearRampToValueAtTime(0, audioContext.currentTime + 0.3);
    
    oscillator.connect(gainNode);
    gainNode.connect(audioContext.destination);
    
    oscillator.start();
    oscillator.stop(audioContext.currentTime + 0.3);
}

// Form submission handling
if (loginForm) {
    loginForm.addEventListener('submit', (e) => {
        if (!validateForm(loginForm)) {
            e.preventDefault();
        }
    });
}

if (registerForm) {
    registerForm.addEventListener('submit', (e) => {
        if (!validateForm(registerForm)) {
            e.preventDefault();
        }
    });
}

// Input animation effects
const inputs = document.querySelectorAll('.input-group input');
inputs.forEach(input => {
    input.addEventListener('focus', () => {
        const icon = input.parentElement.querySelector('.input-icon i');
        icon.style.color = '#9370db';
        icon.style.textShadow = '0 0 10px rgba(147, 112, 219, 0.5)';
    });
    
    input.addEventListener('blur', () => {
        const icon = input.parentElement.querySelector('.input-icon i');
        if (!input.value) {
            icon.style.color = '';
            icon.style.textShadow = '';
        }
    });
});

// Handle resize for responsive stars
window.addEventListener('resize', () => {
    starsContainer.innerHTML = '';
    createStars();
}); 