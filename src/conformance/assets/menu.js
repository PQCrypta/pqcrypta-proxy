'use strict';

// Menu functionality - Quantum Control Panel System
// CSP-compliant, cutting-edge implementation
// Fully isolated to prevent conflicts with page scripts

(function() {
    // Create isolated scope to prevent global conflicts

// Quantum Control Panel State
const QuantumMenu = {
    isOpen: false,
    expandedSections: new Set(),
    currentPage: '',

    init() {
        this.detectCurrentPage();
        this.setupEventListeners();
        this.setupExpandableSections();
        this.initThemeSystem();
        this.updateAuthenticationState();
    },

    initThemeSystem() {
        // Load saved theme from localStorage or default to 'electric-blue'
        const savedTheme = localStorage.getItem('quantum-menu-theme') || 'electric-blue';
        this.applyTheme(savedTheme);

        // Set the selector to the saved theme
        const selector = document.getElementById('menuThemeSelector');
        if (selector) {
            selector.value = savedTheme;
            selector.addEventListener('change', (e) => {
                this.applyTheme(e.target.value);
            });
        }

    },

    applyTheme(themeName) {
        const wrapper = document.querySelector('.quantum-menu-wrapper');
        if (!wrapper) return;

        // Remove all theme attributes
        wrapper.removeAttribute('data-theme');

        // Apply new theme (electric-blue is default, no attribute needed)
        if (themeName !== 'electric-blue') {
            wrapper.setAttribute('data-theme', themeName);
        }

        // Save to localStorage
        localStorage.setItem('quantum-menu-theme', themeName);

        // Optional: Add a subtle transition effect
        wrapper.style.transition = 'all 0.5s ease';
        setTimeout(() => {
            wrapper.style.transition = '';
        }, 500);
    },

    detectCurrentPage() {
        // Use pathname only — strips hash (#overview) and query strings automatically
        const currentPath = window.location.pathname.split('#')[0].split('?')[0];

        // Fallback map for pages NOT present in the server-rendered nav (auth,
        // legal, utility, deep sub-pages). The live nav links below are the single
        // source of truth and OVERRIDE these — so a stale entry here can never win
        // against the actual menu, and nav-page titles can't drift from menu.php.
        const fallbackMap = {
            // Fun animations - most specific paths first
            '/fun/cosmicfluidsimulation/': '🌌 Cosmic Fluid',
            '/fun/dynamicquantumgrid/': '⚡ Quantum Grid',
            '/fun/fractaltree/': '🌳 Fractal Tree',
            '/fun/neuralnetwork/': '🤖 Neural Network',
            '/fun/neuralchaosgrid/': '🧠 Neural Chaos',
            '/fun/particlesystem/': '✨ Particles',
            '/fun/': '✨ Quantum Sandbox',
            // Quantum Morphic Field Explorer
            '/quantum_morphic_field_explorer/': '⚛️ Quantum Field',
            // Legal pages
            '/legal/pqcryptaprivacy.php': '🔐 Privacy',
            '/legal/pqcryptalegal.php': '⚖️ Legal',
            // Security & Threat pages
            '/threat-bot/': '🛡️ Threat Dashboard',
            '/bot-threat-remediation/': '🤖 Bot Remediation',
            // Other specific pages
            '/streaming/': '🚀 WebTransport Test',
            '/speedtest/': '🌐 Speed Test',
            '/wt-telemetry/': '📡 Telemetry Wall',
            '/entropy/': '🎲 Entropy',
            '/pqcchallengemode/': '🔐 Challenge',
            '/security-systems/': '🛡️ Security',
            '/key-vault/': '🔐 KeyVault',
            '/news/': '📰 News',
            '/share/': '🔐 Encrypt & Share',
            '/encryption/': '🔒 Encryption',
            '/compression/': '🗜️ Compression',
            // '/blockchain/': '⛓️ Blockchain', // [DISABLED 2026-07-20: blockchain feature commented out platform-wide]
            '/analytics/': '📊 Analytics',
            '/health/': '🩺 Health Monitor',
            '/monitor/': '📡 System Telemetry',
            '/dashboard/': '📊 Dashboard',
            '/docs/': '📖 Documentation',
            // Longest prefix wins below, so each sub-page must be listed as well or
            // it resolves to its parent's label. guide.php only gained the menu
            // later, which is why its entry was dropped once as dead and is back.
            '/discovery/offline/': '📴 Air-Gap Mode',
            '/discovery/guide.php': '📘 Deployment Guide',
            '/discovery/': '🔍 Discovery Agent',
            '/contact/': '📧 Contact',
            '/resume/': '🧙‍♂️ Resume',
            '/signup.php': '📝 Sign Up',
            '/login.php': '🔑 Login',
            '/about.php': 'ℹ️ About',
            '/music/music-description.php': '📖 Quantum Chronicles',
            '/music/': '🎵 Music',
            '/regex/': '🔍 Regex',
            '/sql/': '🗃️ SQL',
            '/pqc-ready/': '🔬 PQC Scanner',
            '/http3-quic/': '⚡ HTTP/3 Analyzer',
            '/why/': '❓ Why PQC?',
            '/what/': '📋 What?',
            '/pqcbv1/': '📄 PQC Binary WP',
            '/pqcproxy/': '🌐 PQC Proxy WP',
            '/pentests/': '🎯 Red Team Tests',
            '/circuit-breaker/': '⚡ Circuit Breaker',
            '/handshake/': '🪞 Handshake Mirror',
            '/ja4/': '🫆 JA4 Directory',
            '/conformance/': '🧪 H3 Conformance',
            '/cbom/': '📋 CBOM Validator',
            '/masque/': '🕳️ MASQUE Relay',
            '/pqc-tickets/': '🎟️ PQC Tickets',
            // Longest prefix wins, so '/pqc-tickets/' above must stay ahead of
            // nothing in particular — but '/pqc/' below must not shadow it, and
            // does not, because matching is on the full normalised path.
            '/pqc/': '📜 PQC Cert Chain',
            '/http3-whitepaper/': '🔬 QUIC Anatomy WP',
            '/mice/': '🖱️ Mice',
            '/fun/cubeanimation/': '🧊 Cube Animation',
            '/fun/fluidanimation/': '🌊 Fluid Animation',
            '/fun/matrixrainanimation/': '🌧️ Matrix Rain',
            '/fun/backgrounds/': '🖼️ Backgrounds',
            '/quic-whitepaper/': '🌐 QUIC vs TCP WP',
            '/multipath-whitepaper/': '🛣️ Multipath QUIC WP',
            '/http-smuggling/': '🕳️ HTTP Smuggling',
            '/quic-hardening/': '🛡️ QUIC Hardening',
            '/traffic-analysis/': '📡 Traffic Analysis',
            '/share-whitepaper/': '🔐 Share WP',
            '/benchmark/': '📊 PQC Benchmark',
            '/benchmark-analysis/': '📈 Benchmark Stats',
            '/pr/': '📰 Press',
            // Home - must be last and uses exact match only
            '/index.php': '🏠 Home',
            '/': '🏠 Home'
        };

        // Single source of truth: derive path -> "icon label" from the actual
        // server-rendered nav links (menu.php). This is what stops the menu.js map
        // and the menu.php links from ever drifting apart again — the rendered
        // links win over the fallback map above.
        const domMap = {};
        document.querySelectorAll('.nav-link[href]').forEach(a => {
            try {
                let p = new URL(a.getAttribute('href'), window.location.origin).pathname;
                p = p.replace(/index\.php$/, '');
                if (!p.endsWith('/')) p += '/';
                const icon = (a.querySelector('.nav-icon')?.textContent || '').trim();
                const label = (a.querySelector('.nav-label')?.textContent || '').trim();
                if (label) domMap[p] = (icon ? icon + ' ' : '') + label;
            } catch (e) { /* skip unparseable hrefs (e.g. #anchors) */ }
        });

        const pageMap = { ...fallbackMap, ...domMap };

        // Normalise current path: strip trailing /index.php, ensure trailing slash
        // so /share-whitepaper, /share-whitepaper/ and /share-whitepaper/index.php all match
        const normalizedCurrent = currentPath
            .replace(/\/index\.php$/, '/')
            .replace(/([^/])$/, '$1/');

        // Find matching page — longest prefix wins (most specific)
        let pageName = '⚡ Navigation';
        let bestMatch = '';

        for (const [path, name] of Object.entries(pageMap)) {
            // Home paths must use exact match — every URL starts with '/'
            // so startsWith('/') would falsely match every page
            if (path === '/' || path === '/index.php') {
                if (normalizedCurrent === '/') {
                    bestMatch = path;
                    pageName = name;
                }
                continue;
            }

            const normalizedPath = path.endsWith('/') ? path : path + '/';

            if (normalizedCurrent.startsWith(normalizedPath)) {
                if (path.length > bestMatch.length) {
                    bestMatch = path;
                    pageName = name;
                }
            }
        }

        this.currentPage = pageName;
        this.updatePageName();
    },

    updatePageName() {
        const pageNameEl = document.getElementById('currentPageName');
        if (pageNameEl) {
            pageNameEl.textContent = this.currentPage;
        }
    },

    setupEventListeners() {
        // Main control button
        const controlBtn = document.getElementById('quantumControlBtn');
        const overlay = document.getElementById('quantumControlOverlay');
        const panel = document.getElementById('quantumControlPanel');
        const closeBtn = document.getElementById('panelCloseBtn');

        if (controlBtn) {
            controlBtn.addEventListener('click', () => this.togglePanel());
        }

        if (overlay) {
            overlay.addEventListener('click', () => this.closePanel());
        }

        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.closePanel());
        }

        // Action buttons - scoped to quantum menu only
        const wrapper = document.querySelector('.quantum-menu-wrapper');
        if (wrapper) {
            const actionBtns = wrapper.querySelectorAll('.action-btn, .action-btn-compact');
            actionBtns.forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const action = btn.getAttribute('data-action');
                    this.handleAction(action);
                });
            });

            // Prevent disabled links from being clicked (delegated event)
            wrapper.addEventListener('click', (e) => {
                const link = e.target.closest('.nav-link.disabled');
                if (link) {
                    e.preventDefault();
                    e.stopPropagation();
                    return false;
                }
            });

            // Handle logout link (delegated event)
            const logoutLink = document.getElementById('logoutLink');
            if (logoutLink) {
                logoutLink.addEventListener('click', (e) => {
                    e.preventDefault();
                    if (!logoutLink.classList.contains('disabled')) {
                        this.handleLogout();
                    }
                });
            }
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isOpen) {
                this.closePanel();
            }
        });
    },

    setupExpandableSections() {
        // Scoped to quantum menu only
        const wrapper = document.querySelector('.quantum-menu-wrapper');
        if (!wrapper) return;

        const expandableTitles = wrapper.querySelectorAll('.section-title.expandable');

        expandableTitles.forEach(title => {
            title.addEventListener('click', () => {
                const sectionId = title.getAttribute('data-section');
                const section = wrapper.querySelector(`#${sectionId}-section`);

                if (section) {
                    const isExpanded = this.expandedSections.has(sectionId);

                    if (isExpanded) {
                        // Collapse
                        section.classList.add('collapsed');
                        title.classList.remove('expanded');
                        this.expandedSections.delete(sectionId);
                    } else {
                        // Expand
                        section.classList.remove('collapsed');
                        title.classList.add('expanded');
                        this.expandedSections.add(sectionId);
                    }
                }
            });
        });

        // Auto-expand any section that contains an active nav link (current page)
        const activeLinks = wrapper.querySelectorAll('.nav-link.active');
        activeLinks.forEach(link => {
            const section = link.closest('.collapsible');
            if (section && section.classList.contains('collapsed')) {
                section.classList.remove('collapsed');
                const sectionId = section.id.replace('-section', '');
                const title = wrapper.querySelector(`.section-title[data-section="${sectionId}"]`);
                if (title) title.classList.add('expanded');
                this.expandedSections.add(sectionId);
            }
        });
    },

    togglePanel() {
        if (this.isOpen) {
            this.closePanel();
        } else {
            this.openPanel();
        }
    },

    openPanel() {
        const btn = document.getElementById('quantumControlBtn');
        const overlay = document.getElementById('quantumControlOverlay');
        const panel = document.getElementById('quantumControlPanel');

        if (btn) btn.classList.add('active');
        if (overlay) overlay.classList.add('active');
        if (panel) panel.classList.add('active');

        document.body.style.overflow = 'hidden';
        this.isOpen = true;

        // Add quantum particles effect
        this.createQuantumParticles();
    },

    closePanel() {
        const btn = document.getElementById('quantumControlBtn');
        const overlay = document.getElementById('quantumControlOverlay');
        const panel = document.getElementById('quantumControlPanel');

        if (btn) btn.classList.remove('active');
        if (overlay) overlay.classList.remove('active');
        if (panel) panel.classList.remove('active');

        document.body.style.overflow = '';
        this.isOpen = false;
    },

    handleAction(action) {
        if (action === 'webgpu-check') {
            this.closePanel();
            if (window.webgpuDetector) {
                window.webgpuDetector.run(true);
            }
        } else if (action === 'error-pages') {
            this.closePanel();
            if (typeof openErrorMenu === 'function') {
                openErrorMenu();
            }
        }
    },

    async updateAuthenticationState() {
        // Check authentication via API call with httpOnly cookies (not localStorage)
        const wrapper = document.querySelector('.quantum-menu-wrapper');
        if (!wrapper) return;

        const signupLink = wrapper.querySelector('a[href*="signup.php"]');
        const loginLink = wrapper.querySelector('a[href*="login.php"]');
        const dashboardLink = wrapper.querySelector('a[href*="dashboard"]');
        const logoutLink = wrapper.querySelector('#logoutLink');

        try {
            // Build headers - include Bearer token from localStorage if available
            const authHeaders = { 'Accept': 'application/json' };
            const storedToken = localStorage.getItem('auth_token');
            if (storedToken) {
                authHeaders['Authorization'] = 'Bearer ' + storedToken;
            }

            // Call API with credentials and Bearer token
            const response = await fetch('https://api.pqcrypta.com/auth', {
                credentials: 'include',
                headers: authHeaders
            });

            // Must check JSON body - API returns 200 OK with authenticated: false when not logged in
            let isLoggedIn = false;
            if (response.ok) {
                const data = await response.json();
                isLoggedIn = data.authenticated === true;
            }

            if (isLoggedIn) {
                // User is logged in - disable signup and login, enable dashboard and logout
                if (signupLink) signupLink.classList.add('disabled');
                if (loginLink) loginLink.classList.add('disabled');
                if (dashboardLink) dashboardLink.classList.remove('disabled');
                if (logoutLink) logoutLink.classList.remove('disabled');
            } else {
                // User is not logged in - enable signup and login, disable dashboard and logout
                if (signupLink) signupLink.classList.remove('disabled');
                if (loginLink) loginLink.classList.remove('disabled');
                if (dashboardLink) dashboardLink.classList.add('disabled');
                if (logoutLink) logoutLink.classList.add('disabled');
            }
        } catch (error) {
            // On error, assume not logged in
            console.warn('Auth check failed:', error);
            if (signupLink) signupLink.classList.remove('disabled');
            if (loginLink) loginLink.classList.remove('disabled');
            if (dashboardLink) dashboardLink.classList.add('disabled');
            if (logoutLink) logoutLink.classList.add('disabled');
        }
    },

    async handleLogout() {
        // Close the panel first
        this.closePanel();

        // Update menu state immediately to show logged-out state
        const wrapper = document.querySelector('.quantum-menu-wrapper');
        if (wrapper) {
            const signupLink = wrapper.querySelector('a[href*="signup.php"]');
            const loginLink = wrapper.querySelector('a[href*="login.php"]');
            const dashboardLink = wrapper.querySelector('a[href*="dashboard"]');
            const logoutLink = wrapper.querySelector('#logoutLink');

            // Set logged-out state immediately
            if (signupLink) signupLink.classList.remove('disabled');
            if (loginLink) loginLink.classList.remove('disabled');
            if (dashboardLink) dashboardLink.classList.add('disabled');
            if (logoutLink) logoutLink.classList.add('disabled');
        }

        // Get token before clearing so we can invalidate server-side
        const logoutToken = localStorage.getItem('auth_token');

        // Clear localStorage auth data first
        localStorage.removeItem('auth_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user_data');

        try {
            // Call API logout directly with Bearer token to invalidate server session
            if (logoutToken) {
                await fetch('https://api.pqcrypta.com/auth/logout', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Authorization': 'Bearer ' + logoutToken,
                        'Content-Type': 'application/json'
                    }
                });
            }

            // Also call logout.php to clear PHP session and httpOnly cookies
            await fetch('/auth/logout.php', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
        } catch (e) {
            console.warn('Logout failed:', e);
        }

        // Redirect to home page
        window.location.href = '/';
    },

    createQuantumParticles() {
        const panel = document.getElementById('quantumControlPanel');
        const wrapper = document.querySelector('.quantum-menu-wrapper');
        if (!panel || !wrapper) return;

        // Create 20 quantum particles - scoped to wrapper
        for (let i = 0; i < 20; i++) {
            setTimeout(() => {
                const particle = document.createElement('div');
                particle.className = 'quantum-particle';

                // Random position around the panel
                const rect = panel.getBoundingClientRect();
                particle.style.left = (rect.left + Math.random() * rect.width) + 'px';
                particle.style.top = (rect.top + Math.random() * rect.height) + 'px';

                // Append to wrapper instead of body to keep scoped
                wrapper.appendChild(particle);

                // Animate
                requestAnimationFrame(() => {
                    particle.style.opacity = '1';
                    particle.style.transform = `translateY(-${50 + Math.random() * 50}px)`;
                });

                // Remove after animation
                setTimeout(() => {
                    particle.remove();
                }, 1000);
            }, i * 50);
        }
    }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Quantum Control Panel
    QuantumMenu.init();

    // Legacy dropdown support
    const animationSelect = document.getElementById('animation-select');
    if (animationSelect) {
        animationSelect.addEventListener('change', function() {
            handleMenuChange(this.value);
        });
    }

    // Error menu close button
    const errorCloseBtn = document.getElementById('error-close-btn');
    if (errorCloseBtn) {
        errorCloseBtn.addEventListener('click', function() {
            closeErrorMenu();
        });
    }
});

})(); // End isolated scope

// Legacy support for old dropdown menu - exposed globally for compatibility
function handleMenuChange(url) {
    if (url === "error-pages") {
        if (typeof openErrorMenu === 'function') {
            openErrorMenu();
        }
        const select = document.getElementById('animation-select');
        if (select) select.selectedIndex = 0;
    } else if (url === "webgpu-check") {
        if (window.webgpuDetector) {
            window.webgpuDetector.run(true);
        }
        const select = document.getElementById('animation-select');
        if (select) select.selectedIndex = 0;
    } else if (url && url !== window.location.href) {
        window.location.href = url;
    }
}

function closeErrorMenu() {
    const overlay = document.getElementById('errorMenuOverlay');
    const menu = document.getElementById('errorPagesMenu');

    if (overlay) overlay.classList.remove('active');
    if (menu) menu.classList.remove('active');
    document.body.classList.remove('menu-open');
}
// ========================================
// QUANTUM 3D CARD INTERACTIONS
// CSP-Compliant mouse tracking for 3D tilt
// ========================================

class Quantum3DCards {
    constructor() {
        this.cards = [];
        this.init();
    }

    init() {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setupCards());
        } else {
            this.setupCards();
        }
    }

    setupCards() {
        // Find all 3D cards
        const cardElements = document.querySelectorAll('.quantum-3d-card');
        
        cardElements.forEach(card => {
            this.initializeCard(card);
        });
    }

    initializeCard(card) {
        const inner = card.querySelector('.quantum-3d-inner');
        if (!inner) return;

        let isHovering = false;
        let animationFrame = null;

        // Mouse enter - start tracking
        card.addEventListener('mouseenter', () => {
            isHovering = true;
            card.classList.add('card-tracking');
        });

        // Mouse move - update 3D transform
        card.addEventListener('mousemove', (e) => {
            if (!isHovering) return;

            // Cancel previous animation frame
            if (animationFrame) {
                cancelAnimationFrame(animationFrame);
            }

            // Schedule new calculation
            animationFrame = requestAnimationFrame(() => {
                const rect = card.getBoundingClientRect();
                const cardWidth = rect.width;
                const cardHeight = rect.height;
                
                // Calculate mouse position relative to card center
                const mouseX = e.clientX - rect.left;
                const mouseY = e.clientY - rect.top;
                
                // Normalize to -1 to 1 range
                const normalizedX = (mouseX / cardWidth - 0.5) * 2;
                const normalizedY = (mouseY / cardHeight - 0.5) * 2;
                
                // Calculate tilt angles (max 20 degrees)
                const tiltX = normalizedX * 20;
                const tiltY = -normalizedY * 20;
                const translateZ = 30; // Lift on hover
                
                // Apply transform using CSS custom properties
                card.style.setProperty('--tilt-x', `${tiltX}deg`);
                card.style.setProperty('--tilt-y', `${tiltY}deg`);
                card.style.setProperty('--tilt-z', `${translateZ}px`);

                // Add CSS class for tilt effect
                inner.classList.add('card-tilted');
            });
        });

        // Mouse leave - reset transform
        card.addEventListener('mouseleave', () => {
            isHovering = false;

            if (animationFrame) {
                cancelAnimationFrame(animationFrame);
                animationFrame = null;
            }

            // Smooth transition back to normal using CSS classes
            card.classList.remove('card-tracking');
            inner.classList.remove('card-tilted');

            // Clear custom properties
            card.style.removeProperty('--tilt-x');
            card.style.removeProperty('--tilt-y');
            card.style.removeProperty('--tilt-z');
        });

        // Add touch support for mobile
        card.addEventListener('touchstart', (e) => {
            e.preventDefault();
            isHovering = true;
        });

        card.addEventListener('touchmove', (e) => {
            if (!isHovering) return;
            e.preventDefault();
            
            const touch = e.touches[0];
            const rect = card.getBoundingClientRect();
            const cardWidth = rect.width;
            const cardHeight = rect.height;
            
            const mouseX = touch.clientX - rect.left;
            const mouseY = touch.clientY - rect.top;
            
            const normalizedX = (mouseX / cardWidth - 0.5) * 2;
            const normalizedY = (mouseY / cardHeight - 0.5) * 2;
            
            const tiltX = normalizedX * 15; // Less tilt on mobile
            const tiltY = -normalizedY * 15;
            const translateZ = 20;
            
            inner.style.transform = `
                rotateY(${tiltX}deg) 
                rotateX(${tiltY}deg) 
                translateZ(${translateZ}px)
            `;
        });

        card.addEventListener('touchend', () => {
            isHovering = false;
            inner.style.transform = 'rotateY(0deg) rotateX(0deg) translateZ(0px)';
        });

        // Store card reference
        this.cards.push({
            element: card,
            inner: inner
        });
    }

    // Add pulsing depth effect
    startQuantumPulse() {
        let pulsePhase = 0;
        
        const pulse = () => {
            pulsePhase += 0.02;
            
            this.cards.forEach(({inner}, index) => {
                const offset = index * Math.PI / 2;
                const depth = Math.sin(pulsePhase + offset) * 5;
                
                // Only apply if not being hovered
                if (inner.style.transform.includes('rotateY(0deg)')) {
                    inner.style.transform = `translateZ(${depth}px)`;
                }
            });
            
            requestAnimationFrame(pulse);
        };
        
        pulse();
    }
}

// Initialize when menu is ready
if (typeof QuantumMenu !== 'undefined') {
    // Wait for menu to initialize
    setTimeout(() => {
        window.quantum3DCards = new Quantum3DCards();
        // Optional: start subtle pulsing effect
        // window.quantum3DCards.startQuantumPulse();
    }, 100);
} else {
    // Fallback: initialize on DOM ready
    window.quantum3DCards = new Quantum3DCards();
}
