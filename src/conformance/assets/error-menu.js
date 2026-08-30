// Quantum Error Portal - ES6 Interactive Menu
// Guard against multiple declarations
if (typeof QuantumErrorPortal === 'undefined') {
    class QuantumErrorPortal {
    constructor() {
        this.overlay = null;
        this.menu = null;
        this.isOpen = false;
        this.particles = [];
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.createParticleSystem();
    }

    setupEventListeners() {
        // Escape key handler
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isOpen) this.close();
        });

        // Prevent menu close on menu click
        document.addEventListener('click', (e) => {
            if (this.isOpen && e.target.id === 'errorMenuOverlay') {
                this.close();
            }
        });
    }

    open() {
        if (this.isOpen) return;

        this.overlay = document.getElementById('errorMenuOverlay');
        this.menu = document.getElementById('errorPagesMenu');
        
        if (!this.overlay || !this.menu) return;

        this.isOpen = true;
        document.body.classList.add('menu-open');
        
        // Trigger animations
        this.overlay.classList.add('active');
        this.menu.classList.add('active');
        
        // Animate menu items with stagger
        this.animateMenuItems();
        this.startParticleEffect();
    }

    close() {
        if (!this.isOpen) return;

        this.isOpen = false;
        document.body.classList.remove('menu-open');
        
        this.overlay?.classList.remove('active');
        this.menu?.classList.remove('active');
        this.stopParticleEffect();
    }

    animateMenuItems() {
        const items = this.menu.querySelectorAll('.error-menu-item');
        items.forEach((item, index) => {
            item.classList.add('menu-item-enter');
            
            setTimeout(() => {
                item.classList.remove('menu-item-enter');
                item.classList.add('menu-item-active');
            }, 100 + index * 50);
        });
    }

    createParticleSystem() {
        // CSS classes are now defined in the main stylesheet
        // No need to create dynamic styles that violate CSP
    }

    startParticleEffect() {
        if (!this.menu) return;
        
        this.particleInterval = setInterval(() => {
            this.createParticle();
        }, 200);
    }

    createParticle() {
        if (!this.menu) return;

        const particle = document.createElement('div');
        const particleId = `particle-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        particle.className = 'quantum-particle';
        particle.id = particleId;

        const rect = this.menu.getBoundingClientRect();
        const left = rect.left + Math.random() * rect.width;
        const top = rect.bottom - 10;

        // Create or get dynamic stylesheet
        if (!this.dynamicStyles) {
            this.dynamicStyles = document.createElement('style');
            // Try to get CSP nonce from existing scripts
            const nonce = document.querySelector('script[nonce]')?.nonce || document.querySelector('style[nonce]')?.nonce;
            if (nonce) {
                this.dynamicStyles.setAttribute('nonce', nonce);
            }
            this.dynamicStyles.id = 'quantum-particle-styles';
            document.head.appendChild(this.dynamicStyles);
        }

        // Add CSS rule for this particle
        const rule = `#${particleId} { left: ${left}px; top: ${top}px; animation: quantumFloat 2s ease-out forwards; }`;
        this.dynamicStyles.textContent += rule + '\n';

        document.body.appendChild(particle);

        setTimeout(() => {
            particle.remove();
            // Clean up CSS rule
            if (this.dynamicStyles) {
                this.dynamicStyles.textContent = this.dynamicStyles.textContent.replace(rule + '\n', '');
            }
        }, 2000);
    }

    stopParticleEffect() {
        if (this.particleInterval) {
            clearInterval(this.particleInterval);
            this.particleInterval = null;
        }
    }
}

// Initialize portal inside the guard
window.QuantumErrorPortal = QuantumErrorPortal;
window.quantumPortalInstance = new QuantumErrorPortal();
}

// Error-specific menu functions
function openErrorMenu() {
    if (window.quantumPortalInstance) {
        window.quantumPortalInstance.open();
    }
}

// Global exports for error menu functionality
window.openErrorMenu = openErrorMenu;
// Set quantumPortal reference (will be undefined if class wasn't initialized)
window.quantumPortal = typeof window.quantumPortalInstance !== 'undefined' ? window.quantumPortalInstance : null;

// The menu dropdown is handled by menu.js
// This file only provides the openErrorMenu function that menu.js calls