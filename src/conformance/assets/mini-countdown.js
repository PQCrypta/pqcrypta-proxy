/**
 * Mini Quantum Countdown Widget
 * Compact countdown timer for navigation menu
 */

(function() {
    'use strict';

    // Q-Day: When quantum computers can decrypt today's encrypted data
    const qDay = new Date('2030-01-01T00:00:00Z').getTime();

    // Cache DOM elements
    const yearsDisplay = document.getElementById('mini-qc-years');
    const daysDisplay = document.getElementById('mini-qc-days');
    const hoursDisplay = document.getElementById('mini-qc-hours');
    const minutesDisplay = document.getElementById('mini-qc-minutes');
    const secondsDisplay = document.getElementById('mini-qc-seconds');
    const msDisplay = document.getElementById('mini-qc-ms');
    const dateDisplay = document.getElementById('widget-date');
    const timeDisplay = document.getElementById('widget-time');

    if (!yearsDisplay || !daysDisplay || !hoursDisplay || !minutesDisplay ||
        !secondsDisplay || !msDisplay || !dateDisplay || !timeDisplay) {
        return; // Exit if elements not found
    }

    // State tracking for glow effect
    let lastValues = {
        years: null,
        days: null,
        hours: null,
        minutes: null,
        seconds: null,
        ms: null
    };

    function updateCountdown() {
        const now = Date.now();
        const delta = qDay - now;

        if (delta < 0) {
            yearsDisplay.textContent = '0';
            daysDisplay.textContent = '0';
            hoursDisplay.textContent = '00';
            minutesDisplay.textContent = '00';
            secondsDisplay.textContent = '00';
            msDisplay.textContent = '000';
            return;
        }

        // Calculate time units
        const totalDays = Math.floor(delta / 86400000);
        const years = Math.floor(totalDays / 365);
        const days = totalDays % 365;
        const hours = Math.floor((delta % 86400000) / 3600000);
        const minutes = Math.floor((delta % 3600000) / 60000);
        const seconds = Math.floor((delta % 60000) / 1000);
        const ms = Math.floor(delta % 1000);

        // Update countdown with glow effect on change
        updateValue(yearsDisplay, years, 'years');
        updateValue(daysDisplay, days, 'days');
        updateValue(hoursDisplay, String(hours).padStart(2, '0'), 'hours');
        updateValue(minutesDisplay, String(minutes).padStart(2, '0'), 'minutes');
        updateValue(secondsDisplay, String(seconds).padStart(2, '0'), 'seconds');
        updateValue(msDisplay, String(ms).padStart(3, '0'), 'ms');
    }

    function updateValue(element, value, key) {
        if (lastValues[key] !== value) {
            element.textContent = value;

            // Add glow effect
            element.classList.add('glow');
            setTimeout(() => element.classList.remove('glow'), 150);

            lastValues[key] = value;
        }
    }

    function updateDateTime() {
        const now = new Date();

        // Format date: Dec 14, 2025
        const dateOptions = { month: 'short', day: 'numeric', year: 'numeric' };
        const formattedDate = now.toLocaleDateString('en-US', dateOptions);

        // Format time: 14:30:45
        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        const seconds = String(now.getSeconds()).padStart(2, '0');
        const formattedTime = `${hours}:${minutes}:${seconds}`;

        dateDisplay.textContent = formattedDate;
        timeDisplay.textContent = formattedTime;
    }

    // Update countdown using requestAnimationFrame for smooth ms updates
    function tick() {
        updateCountdown();
        updateDateTime();
        requestAnimationFrame(tick);
    }

    // Start the animation loop
    requestAnimationFrame(tick);
})();
