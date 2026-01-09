// C:\inventory\app\static\js\token-timer.js

class TokenTimerManager {
  constructor(options = {}) {
    // Default options
    this.options = {
      showInNavbar: true,
      showInDropdown: true,
      autoRefreshThreshold: 60, // seconds
      warningThreshold: 300, // 5 minutes
      alertThreshold: 120, // 2 minutes
      checkInterval: 1000, // 1 second
      statusCheckInterval: 30000, // 30 seconds
      expiredRedirectDelay: 600000, // 10 minutes
      ...options,
    }

    // State
    this.tokenExpirySeconds = 0
    this.timerInterval = null
    this.statusCheckInterval = null
    this.isRefreshing = false
    this.lastAlertTime = 0
    this.alertCooldown = 60000 // 1 minute cooldown between alerts
    this.hasShownExpiredModal = false
    this.isRedirecting = false

    // Initialize theme tracking
    this.currentTheme = this.getCurrentThemeFromStorage()

    // Initialize CSS
    this.injectCSS()

    // Initialize
    this.init()
  }

  injectCSS() {
    const css = `
      /* Token Timer Styles */
      .token-timer-green {
        background-color: rgba(12, 94, 216, 0.16) !important;
        color: #3778f0ff !important;
        border: 1px solid rgba(142, 176, 238, 1);
      }

      .token-timer-yellow {
        background-color: rgba(255, 171, 0, 0.16) !important;
        color: #ffab00 !important;
        border: 1px solid rgba(255, 171, 0, 0.3);
      }

      .token-timer-red {
        background-color: rgba(234, 84, 85, 0.16) !important;
        color: #ea5455 !important;
        border: 1px solid rgba(234, 84, 85, 0.3);
      }

      .token-timer-expired {
        background-color: rgba(133, 146, 163, 0.16) !important;
        color: #8592a3 !important;
        border: 1px solid rgba(133, 146, 163, 0.3);
      }

      /* Pulse animation for warning */
      .token-pulse {
        animation: tokenPulse 1s infinite;
      }

      @keyframes tokenPulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
      }

      /* Clickable Timer Container */
      .token-timer-clickable {
        cursor: pointer !important;
        transition: all 0.2s ease !important;
        border-radius: 6px !important;
        padding: 6px 10px !important;
        user-select: none !important;
        margin: 0 2px !important;
      }

      .token-timer-clickable:hover {
        background-color: rgba(255, 255, 255, 0.1) !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15) !important;
      }

      .token-timer-clickable:active {
        transform: translateY(0) !important;
        background-color: rgba(255, 255, 255, 0.15) !important;
      }

      .token-timer-clickable.active {
        background-color: rgba(105, 108, 255, 0.2) !important;
        box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.1) !important;
      }

      /* Timer badge in navbar */
      #navbar-token-timer {
        cursor: pointer;
        transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
        font-family: 'Courier New', monospace;
        font-weight: 600;
        min-width: 70px;
        text-align: center;
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 0.8125rem;
        line-height: 1;
        letter-spacing: 0.3px;
        margin-left: 4px;
      }

      .token-timer-clickable:hover #navbar-token-timer {
        box-shadow: 0 0 0 2px rgba(255, 255, 255, 0.2);
        transform: translateY(-1px);
      }

      /* Text inside clickable area */
      .token-timer-text {
        font-size: 0.85rem !important;
        font-weight: 500;
        font-family: 'Public Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
        white-space: nowrap;
        margin-right: 6px;
        transition: color 0.2s ease;
      }

      .token-timer-clickable:hover .token-timer-text {
        text-decoration: none !important;
      }

      /* Dropdown timer */
      #dropdown-token-timer {
        font-family: 'Courier New', monospace;
        font-weight: 600;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        display: inline-block;
        margin-left: 4px;
        cursor: pointer;
      }

      /* Icon styling */
      .token-timer-clickable .bx-time-five {
        font-size: 1rem !important;
        margin-right: 6px;
        opacity: 0.9;
      }

      /* Session alert modal */
      #session-alert-modal .modal-content {
        border: none;
        border-radius: 0.625rem;
        overflow: hidden;
        box-shadow: 0 0.25rem 1.5rem rgba(22, 28, 45, 0.15);
      }

      #session-alert-modal .modal-header {
        border-bottom: none;
        padding: 1.375rem 1.5rem;
        background: linear-gradient(135deg, #ffab00 0%, #ff9100 100%);
      }

      #session-alert-modal .modal-body {
        padding: 1.75rem 1.5rem;
      }

      #session-alert-modal .modal-footer {
        border-top: none;
        padding: 0 1.5rem 1.5rem;
      }

      #continue-session-btn,
      #logout-now-btn {
        min-width: 160px;
        border-radius: 0.5rem;
        font-weight: 500;
        padding: 0.6875rem 1.5rem;
        font-size: 0.9375rem;
        transition: all 0.23s ease-in-out;
        border-width: 1px;
      }

      #continue-session-btn {
        background: linear-gradient(135deg, #28c76f 0%, #20b363 100%);
        border-color: #28c76f;
      }

      #continue-session-btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 0.375rem 1rem rgba(40, 199, 111, 0.3);
        background: linear-gradient(135deg, #24b864 0%, #1c9f57 100%);
        border-color: #24b864;
      }

      #logout-now-btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 0.375rem 1rem rgba(234, 84, 85, 0.2);
        border-color: #ea5455;
      }

      /* Expired session modal */
      #session-expired-modal .modal-content {
        border: none;
        border-radius: 0.625rem;
        overflow: hidden;
        box-shadow: 0 0.25rem 1.5rem rgba(22, 28, 45, 0.15);
      }

      #session-expired-modal .modal-header {
        border-bottom: none;
        padding: 1.375rem 1.5rem;
        background: linear-gradient(135deg, #ea5455 0%, #e53935 100%);
      }

      #session-expired-modal .modal-body {
        padding: 2rem 1.5rem;
      }

      #session-expired-modal .alert-warning {
        background-color: rgba(255, 171, 0, 0.08);
        border-color: rgba(255, 171, 0, 0.2);
        color: #ffab00;
      }

      #go-to-login-btn {
        border-radius: 0.5rem;
        font-weight: 500;
        padding: 0.75rem 2rem;
        background: linear-gradient(135deg, #6d6d6eff 0%, #6e6e75ff 100%);
        border-color: #525258ff;
        transition: all 0.23s ease-in-out;
      }

      #go-to-login-btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 0.375rem 1rem rgba(105, 108, 255, 0.3);
        background: linear-gradient(135deg, #98ff5dff 0%, #484bf9 100%);
        border-color: #5d60ff;
      }

      /* Token Info Modal */
      #token-info-modal .modal-content {
        border: none;
        border-radius: 0.625rem;
        overflow: hidden;
        box-shadow: 0 0.25rem 1.5rem rgba(22, 28, 45, 0.15);
      }

      #token-info-modal .modal-header {
        border-bottom: none;
        padding: 1rem 1.5rem;
        background: linear-gradient(135deg, #e6e6e6ff 0%rgba(194, 194, 194, 1)ff 100%);
      }

      #token-info-modal .modal-body {
        padding: 1.5rem;
      }

      #modal-timer {
        font-family: 'Courier New', monospace;
        font-weight: bold;
      }

      /* Toast notifications */
      #token-toast-container {
        z-index: 1090;
      }

      .token-toast {
        border-radius: 0.5rem;
        border: 1px solid rgba(0, 0, 0, 0.05);
        margin-bottom: 0.75rem;
        min-width: 320px;
        box-shadow: 0 0.25rem 1rem rgba(22, 28, 45, 0.1);
        backdrop-filter: blur(10px);
      }

      .token-toast.bg-success {
        background-color: rgba(40, 199, 111, 0.95) !important;
        border-color: rgba(40, 199, 111, 0.3);
      }

      .token-toast.bg-danger {
        background-color: rgba(234, 84, 85, 0.95) !important;
        border-color: rgba(234, 84, 85, 0.3);
      }

      .token-toast.bg-warning {
        background-color: rgba(255, 171, 0, 0.95) !important;
        border-color: rgba(255, 171, 0, 0.3);
      }

      .token-toast.bg-info {
        background-color: rgba(105, 108, 255, 0.95) !important;
        border-color: rgba(105, 108, 255, 0.3);
      }

      .token-toast .bx {
        font-size: 1.25rem;
        vertical-align: middle;
      }

      /* Mobile responsive */
      @media (max-width: 768px) {
        .token-timer-clickable {
          padding: 3px 6px !important;
        }

        .token-timer-text {
          font-size: 0.75rem !important;
        }

        #navbar-token-timer {
          font-size: 0.75rem;
          min-width: 65px;
          padding: 5px 8px;
        }

        #continue-session-btn,
        #logout-now-btn {
          min-width: 130px;
          font-size: 0.875rem;
          padding: 0.5625rem 1rem;
        }

        .token-toast {
          min-width: 280px;
          font-size: 0.875rem;
          margin: 0.5rem;
        }

        #session-alert-modal .modal-dialog,
        #session-expired-modal .modal-dialog,
        #token-info-modal .modal-dialog {
          margin: 1rem;
        }
      }

      /* Dark mode support */
      [data-bs-theme='dark'] .token-timer-green {
        background-color: rgba(40, 199, 111, 0.25) !important;
        color: #4cd964 !important;
      }

      [data-bs-theme='dark'] .token-timer-yellow {
        background-color: rgba(255, 171, 0, 0.25) !important;
        color: #ffd54f !important;
      }

      [data-bs-theme='dark'] .token-timer-red {
        background-color: rgba(234, 84, 85, 0.25) !important;
        color: #ff8a80 !important;
      }

      [data-bs-theme='dark'] .token-timer-expired {
        background-color: rgba(158, 158, 158, 0.25) !important;
        color: #b0bec5 !important;
      }

      [data-bs-theme='dark'] .token-timer-clickable:hover {
        background-color: rgba(255, 255, 255, 0.05) !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3) !important;
      }

      [data-bs-theme='dark'] .token-timer-clickable:hover .token-timer-text {
        color: #cfd3ec !important;
      }

      [data-bs-theme='dark'] .token-timer-clickable.active {
        background-color: rgba(105, 108, 255, 0.15) !important;
      }

      [data-bs-theme='dark'] .token-toast {
        border-color: rgba(255, 255, 255, 0.1);
      }

      [data-bs-theme='dark'] .modal-content {
        background-color: #2f3349;
        color: #cfd3ec;
      }

      [data-bs-theme='dark'] .modal-header {
        color: white;
      }

      [data-bs-theme='dark'] .text-muted {
        color: #7983bb !important;
      }

      /* Animation for modal entrance */
      @keyframes modalSlideIn {
        from {
          opacity: 0;
          transform: translateY(-30px) scale(0.95);
        }
        to {
          opacity: 1;
          transform: translateY(0) scale(1);
        }
      }

      .modal.fade.show .modal-dialog {
        animation: modalSlideIn 0.3s ease-out;
      }

      /* Animation for toast entrance */
      @keyframes toastSlideIn {
        from {
          opacity: 0;
          transform: translateX(100%);
        }
        to {
          opacity: 1;
          transform: translateX(0);
        }
      }

      .token-toast {
        animation: toastSlideIn 0.3s ease-out;
      }

      /* Mobile touch feedback */
      @media (hover: none) and (pointer: coarse) {
        .token-timer-clickable:active {
          background-color: rgba(255, 255, 255, 0.2) !important;
          transform: scale(0.98) !important;
        }
      }
    `

    // Create style element
    const style = document.createElement('style')
    style.id = 'token-timer-styles'
    style.textContent = css

    // Append to head
    if (!document.getElementById('token-timer-styles')) {
      document.head.appendChild(style)
    }
  }

  // NEW: Get current theme from localStorage
  getCurrentThemeFromStorage() {
    try {
      const theme = localStorage.getItem('frest-custom-style')
      return theme === 'dark' ? 'dark' : 'light'
    } catch (e) {
      console.error('Error getting theme from storage:', e)
      return 'light' // default to light
    }
  }

  // NEW: Update text color based on theme
  updateTimerTextColor() {
    const theme = this.getCurrentThemeFromStorage()
    const timerTextElements = document.querySelectorAll('.token-timer-text')

    timerTextElements.forEach((element) => {
      if (theme === 'dark') {
        element.style.color = '#ffffff'
      } else {
        element.style.color = '#5d596c' // warna hitam/abu untuk light mode
      }
    })
  }

  // NEW: Setup theme change listener
  setupThemeChangeListener() {
    // Listen for storage changes (when theme is changed in another tab/window)
    window.addEventListener('storage', (e) => {
      if (e.key === 'frest-custom-style') {
        console.log('Theme changed in storage:', e.newValue)
        this.currentTheme = e.newValue === 'dark' ? 'dark' : 'light'
        this.updateTimerTextColor()
      }
    })

    // Also check when page becomes visible (user returns to tab)
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        const newTheme = this.getCurrentThemeFromStorage()
        if (newTheme !== this.currentTheme) {
          this.currentTheme = newTheme
          this.updateTimerTextColor()
        }
      }
    })
  }

  init() {
    console.log('TokenTimerManager initialized')

    // Initialize click handlers
    this.initClickHandlers()

    // Check token status on load
    this.checkTokenStatus().then(() => {
      // Start timers
      this.startTimers()
    })

    // Add event listeners
    this.addEventListeners()

    // NEW: Setup theme change listener
    this.setupThemeChangeListener()

    // Initial color update
    this.updateTimerTextColor()
  }

  initClickHandlers() {
    // Handle click on entire timer container
    const timerContainer = document.getElementById('navbar-timer-container')
    if (timerContainer) {
      timerContainer.addEventListener('click', (e) => {
        e.preventDefault()
        e.stopPropagation()
        this.handleTimerClick()
      })
    }

    // Handle click on dropdown timer
    const dropdownTimer = document.getElementById('dropdown-token-timer')
    if (dropdownTimer) {
      dropdownTimer.addEventListener('click', (e) => {
        e.preventDefault()
        e.stopPropagation()
        this.handleTimerClick()
      })
    }
  }

  handleTimerClick() {
    console.log('Timer area clicked, remaining seconds:', this.tokenExpirySeconds)

    // Different behavior based on token status
    if (this.tokenExpirySeconds <= 0) {
      // Token expired - show expired modal
      this.showExpiredModal()
    } else if (this.tokenExpirySeconds < this.options.warningThreshold) {
      // Token almost expired - show session alert
      this.showSessionAlert()
    } else {
      // Token still valid - show info panel
      this.showTokenInfoPanel()
    }
  }

  async checkTokenStatus() {
    try {
      const response = await fetch('/api/auth-status', { credentials: 'same-origin' })
      const data = await response.json()

      console.log('Token status:', data)

      if (data.is_logged_in && data.seconds_until_exp) {
        this.tokenExpirySeconds = data.seconds_until_exp

        // Update UI
        this.updateTimerUI()

        // Check if need to show alert
        this.checkForAlert()

        return true
      } else {
        this.tokenExpirySeconds = 0
        this.updateTimerUI()

        // If token expired and we're still on page, redirect to login
        if (data.token_status === 'expired' && !window.location.pathname.includes('/login')) {
          this.showExpiredModal()
        }

        return false
      }
    } catch (error) {
      console.error('Error checking token status:', error)
      return false
    }
  }

  updateTimerUI() {
    // Update navbar timer
    if (this.options.showInNavbar) {
      const navbarTimer = document.getElementById('navbar-token-timer')
      if (navbarTimer) {
        navbarTimer.textContent = this.formatTime(this.tokenExpirySeconds)
        this.updateTimerStyle(navbarTimer, this.tokenExpirySeconds)
      }
    }

    // Update dropdown timer
    if (this.options.showInDropdown) {
      const dropdownTimer = document.getElementById('dropdown-token-timer')
      if (dropdownTimer) {
        dropdownTimer.textContent = this.formatTime(this.tokenExpirySeconds)
        this.updateTimerStyle(dropdownTimer, this.tokenExpirySeconds)
      }
    }

    // NEW: Update text color based on theme
    this.updateTimerTextColor()
  }

  formatTime(seconds) {
    if (seconds <= 0) return 'EXPIRED'

    const hours = Math.floor(seconds / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)
    const secs = Math.floor(seconds % 60)

    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`
  }

  updateTimerStyle(element, seconds) {
    // Remove all existing classes
    element.classList.remove('token-timer-green', 'token-timer-yellow', 'token-timer-red', 'token-timer-expired')

    if (seconds <= 0) {
      element.classList.add('token-timer-expired')
    } else if (seconds < this.options.alertThreshold) {
      element.classList.add('token-timer-red', 'token-pulse')
    } else if (seconds < this.options.warningThreshold) {
      element.classList.add('token-timer-yellow')
    } else {
      element.classList.add('token-timer-green')
    }
  }

  startTimers() {
    // Clear existing intervals
    if (this.timerInterval) clearInterval(this.timerInterval)
    if (this.statusCheckInterval) clearInterval(this.statusCheckInterval)

    // Timer for countdown
    this.timerInterval = setInterval(() => {
      if (this.tokenExpirySeconds > 0) {
        this.tokenExpirySeconds--
        this.updateTimerUI()

        // Check for auto-refresh
        if (this.tokenExpirySeconds === this.options.autoRefreshThreshold) {
          this.showRefreshAlert()
        }

        // Check for final warning
        if (this.tokenExpirySeconds === 30) {
          this.showFinalWarning()
        }
      } else if (this.tokenExpirySeconds === 0) {
        // Token expired
        this.showExpiredModal()
        clearInterval(this.timerInterval)
      }
    }, 1000)

    // Periodic status check (sync with server)
    this.statusCheckInterval = setInterval(() => {
      this.checkTokenStatus()
    }, this.options.statusCheckInterval)
  }

  checkForAlert() {
    const now = Date.now()

    // Check if we should show alert
    if (this.tokenExpirySeconds > 0 && this.tokenExpirySeconds <= this.options.warningThreshold && now - this.lastAlertTime > this.alertCooldown) {
      this.showSessionAlert()
      this.lastAlertTime = now
    }
  }

  showSessionAlert() {
    // Don't show if already showing or refreshing
    if (this.isRefreshing || document.getElementById('session-alert-modal')) {
      return
    }

    const minutesLeft = Math.ceil(this.tokenExpirySeconds / 60)

    // Create modal HTML
    const modalHtml = `
      <div class="modal fade show" id="session-alert-modal" tabindex="-1" style="display: block; background: rgba(0,0,0,0.5);" data-bs-backdrop="static">
        <div class="modal-dialog modal-dialog-centered">
          <div class="modal-content">
            <div class="modal-header bg-warning">
              <h5 class="modal-title text-white">
                <i class="bx bx-time-five me-2"></i>Session Will Expire Soon
              </h5>
            </div>
            <div class="modal-body">
              <div class="text-center mb-3">
                <i class="bx bx-alarm-exclamation display-4 text-warning mb-3"></i>
                <h5>Your session will expire in ${minutesLeft} minute${minutesLeft > 1 ? 's' : ''}</h5>
                <p class="text-muted">Do you want to continue your session?</p>
              </div>
              <div class="text-center">
                <div class="mb-2">
                  <span class="badge bg-label-warning fs-5">
                    ${this.formatTime(this.tokenExpirySeconds)}
                  </span>
                </div>
                <small class="text-muted">Time remaining until auto logout</small>
              </div>
            </div>
            <div class="modal-footer justify-content-center">
              <button type="button" class="btn btn-success btn-lg px-4" id="continue-session-btn">
                <i class="bx bx-refresh me-2"></i>Continue Session
              </button>
              <button type="button" class="btn btn-outline-danger btn-lg px-4" id="logout-now-btn">
                <i class="bx bx-log-out me-2"></i>Logout Now
              </button>
            </div>
          </div>
        </div>
      </div>
    `

    // Add to page
    document.body.insertAdjacentHTML('beforeend', modalHtml)

    // Initialize Bootstrap modal
    const modalElement = document.getElementById('session-alert-modal')
    const modal = new bootstrap.Modal(modalElement)
    modal.show()

    // Add event listeners
    document.getElementById('continue-session-btn').addEventListener('click', () => {
      this.refreshSession()
      modal.hide()
    })

    document.getElementById('logout-now-btn').addEventListener('click', () => {
      window.location.href = '/logout'
    })

    // Auto hide after 30 seconds if no action
    setTimeout(() => {
      if (modalElement && document.body.contains(modalElement)) {
        modal.hide()
      }
    }, 30000)

    // Remove modal from DOM when hidden
    modalElement.addEventListener('hidden.bs.modal', () => {
      modalElement.remove()
    })
  }

  showRefreshAlert() {
    // Show toast notification for auto-refresh
    this.showToast('Session refreshed automatically', 'success')
  }

  showFinalWarning() {
    // Final warning toast
    this.showToast('Session will expire in 30 seconds!', 'danger', 10000)
  }

  showExpiredModal() {
    // Don't show if already showing or already handled
    if (this.hasShownExpiredModal || document.getElementById('session-expired-modal')) {
      console.debug('TokenTimer: expired modal already shown or handled, skipping')
      return
    }

    // Create expired modal HTML
    const modalHtml = `
      <div class="modal fade show" id="session-expired-modal" tabindex="-1" style="display: block; background: rgba(0,0,0,0.5);" data-bs-backdrop="static">
        <div class="modal-dialog modal-dialog-centered">
          <div class="modal-content">
            <div class="modal-header bg-danger">
              <h5 class="modal-title text-white">
                <i class="bx bx-error-alt me-2"></i>Session Expired
              </h5>
            </div>
            <div class="modal-body text-center">
              <i class="bx bx-time display-1 text-danger mb-3"></i>
              <h4 class="mb-3">Your session has expired</h4>
              <p class="text-muted">For security reasons, you have been logged out due to inactivity.</p>
              <div class="alert alert-warning mt-3">
                <i class="bx bx-info-circle me-2"></i>
                Any unsaved work may be lost.
              </div>
            </div>
            <div class="modal-footer justify-content-center">
              <button type="button" class="btn btn-primary btn-lg px-4" id="go-to-login-btn">
                <i class="bx bx-log-in me-2"></i>Go to Login Page
              </button>
            </div>
          </div>
        </div>
      </div>
    `

    // Add to page
    document.body.insertAdjacentHTML('beforeend', modalHtml)

    // Initialize modal
    const modalElement = document.getElementById('session-expired-modal')
    const modal = new bootstrap.Modal(modalElement)
    modal.show()

    // Add event listener
    document.getElementById('go-to-login-btn').addEventListener('click', () => {
      if (!this.isRedirecting) {
        this.isRedirecting = true
        console.debug('TokenTimer: redirecting to /login via go-to-login-btn')
        window.location.href = '/login'
      }
    })

    // Auto redirect after 10 MINUTES (600,000 ms)
    setTimeout(() => {
      if (!this.isRedirecting) {
        this.isRedirecting = true
        console.debug('TokenTimer: auto-redirecting to /login after expiredRedirectDelay')
        window.location.href = '/login'
      }
    }, this.options.expiredRedirectDelay)
    this.hasShownExpiredModal = true
  }

  showTokenInfoPanel() {
    // Create info panel modal
    const modalHtml = `
      <div class="modal fade" id="token-info-modal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered modal-sm">
          <div class="modal-content">
            <div class="modal-header bg-primary">
              <h5 class="modal-title text-white">
                <i class="bx bx-info-circle me-2"></i>Token Information
              </h5>
              <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
              <div class="text-center mb-3">
                <div class="display-4 fw-bold text-primary mb-2" id="modal-timer">
                  ${this.formatTime(this.tokenExpirySeconds)}
                </div>
                <div class="mb-3">
                  <span class="badge ${this.getStatusBadgeClass()} fs-6">
                    ${this.getStatusText()}
                  </span>
                </div>
              </div>
              
              <div class="list-group list-group-flush">
                <div class="list-group-item d-flex justify-content-between">
                  <span>Time Remaining:</span>
                  <span class="fw-bold">${this.formatDetailedTime()}</span>
                </div>
                <div class="list-group-item d-flex justify-content-between">
                  <span>Auto Refresh:</span>
                  <span class="fw-bold">${this.tokenExpirySeconds <= this.options.autoRefreshThreshold ? 'Enabled' : 'Disabled'}</span>
                </div>
                <div class="list-group-item d-flex justify-content-between">
                  <span>Last Check:</span>
                  <span class="fw-bold">${new Date().toLocaleTimeString()}</span>
                </div>
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                Close
              </button>
              <button type="button" class="btn btn-primary" onclick="window.tokenTimer.refreshSession()">
                <i class="bx bx-refresh me-1"></i>Refresh Now
              </button>
            </div>
          </div>
        </div>
      </div>
    `

    // Remove existing modal if any
    const existingModal = document.getElementById('token-info-modal')
    if (existingModal) existingModal.remove()

    // Add to page
    document.body.insertAdjacentHTML('beforeend', modalHtml)

    // Show modal
    const modalElement = document.getElementById('token-info-modal')
    const modal = new bootstrap.Modal(modalElement)
    modal.show()

    // Update timer in modal every second
    const modalTimerElement = document.getElementById('modal-timer')
    if (modalTimerElement) {
      const updateModalTimer = () => {
        if (this.tokenExpirySeconds > 0 && modalElement && document.body.contains(modalElement)) {
          modalTimerElement.textContent = this.formatTime(this.tokenExpirySeconds)
        }
      }

      // Update immediately
      updateModalTimer()

      // Update every second while modal is open
      const intervalId = setInterval(updateModalTimer, 1000)

      // Clear interval when modal is closed
      modalElement.addEventListener('hidden.bs.modal', () => {
        clearInterval(intervalId)
        modalElement.remove()
      })
    }
  }

  getStatusBadgeClass() {
    if (this.tokenExpirySeconds <= 0) {
      return 'bg-danger'
    } else if (this.tokenExpirySeconds < this.options.alertThreshold) {
      return 'bg-warning'
    } else if (this.tokenExpirySeconds < this.options.warningThreshold) {
      return 'bg-info'
    } else {
      return 'bg-success'
    }
  }

  getStatusText() {
    if (this.tokenExpirySeconds <= 0) {
      return 'EXPIRED'
    } else if (this.tokenExpirySeconds < 60) {
      return 'CRITICAL'
    } else if (this.tokenExpirySeconds < 300) {
      return 'WARNING'
    } else {
      return 'ACTIVE'
    }
  }

  formatDetailedTime() {
    if (this.tokenExpirySeconds <= 0) return 'Expired'

    const hours = Math.floor(this.tokenExpirySeconds / 3600)
    const minutes = Math.floor((this.tokenExpirySeconds % 3600) / 60)
    const seconds = this.tokenExpirySeconds % 60

    let result = ''
    if (hours > 0) result += `${hours}h `
    if (minutes > 0) result += `${minutes}m `
    result += `${seconds}s`

    return result.trim()
  }

  async refreshSession() {
    if (this.isRefreshing) return

    this.isRefreshing = true

    try {
      this.showToast('Refreshing session...', 'info')

      const response = await fetch('/api/refresh-token', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const data = await response.json()

      if (data.success) {
        // Update token expiry
        await this.checkTokenStatus()
        this.showToast('Session refreshed successfully!', 'success')
      } else {
        this.showToast('Failed to refresh session: ' + data.message, 'danger')
      }
    } catch (error) {
      console.error('Error refreshing session:', error)
      this.showToast('Error refreshing session', 'danger')
    } finally {
      this.isRefreshing = false
    }
  }

  showToast(message, type = 'info', duration = 5000) {
    // Remove existing toasts with same message
    const existingToasts = document.querySelectorAll('.token-toast')
    existingToasts.forEach((toast) => {
      if (toast.textContent.includes(message)) {
        toast.remove()
      }
    })

    // Create toast HTML
    const toastId = 'toast-' + Date.now()
    const toastHtml = `
      <div class="toast token-toast align-items-center text-white bg-${type} border-0" 
           id="${toastId}" role="alert" aria-live="assertive" aria-atomic="true">
        <div class="d-flex">
          <div class="toast-body">
            <i class="bx ${this.getToastIcon(type)} me-2"></i>
            ${message}
          </div>
          <button type="button" class="btn-close btn-close-white me-2 m-auto" 
                  data-bs-dismiss="toast"></button>
        </div>
      </div>
    `

    // Add to toast container
    let toastContainer = document.getElementById('token-toast-container')
    if (!toastContainer) {
      toastContainer = document.createElement('div')
      toastContainer.id = 'token-toast-container'
      toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3'
      toastContainer.style.zIndex = '9999'
      document.body.appendChild(toastContainer)
    }

    toastContainer.insertAdjacentHTML('beforeend', toastHtml)

    // Show toast
    const toastElement = document.getElementById(toastId)
    const toast = new bootstrap.Toast(toastElement, {
      delay: duration,
      autohide: true,
    })
    toast.show()

    // Remove from DOM after hide
    toastElement.addEventListener('hidden.bs.toast', () => {
      toastElement.remove()
    })
  }

  getToastIcon(type) {
    const icons = {
      success: 'bx-check-circle',
      danger: 'bx-error',
      warning: 'bx-error-alt',
      info: 'bx-info-circle',
    }
    return icons[type] || 'bx-info-circle'
  }

  addEventListeners() {
    // Listen for visibility change (tab switch)
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        // Tab became active, check token
        this.checkTokenStatus()
      }
    })

    // Listen for page focus
    window.addEventListener('focus', () => {
      this.checkTokenStatus()
    })

    // Listen for clicks on document to handle outside clicks
    document.addEventListener('click', (e) => {
      // If clicking outside timer area, remove active state
      if (!e.target.closest('#navbar-timer-container')) {
        const timerContainer = document.getElementById('navbar-timer-container')
        if (timerContainer) {
          timerContainer.classList.remove('active')
        }
      }
    })
  }

  destroy() {
    // Cleanup
    if (this.timerInterval) clearInterval(this.timerInterval)
    if (this.statusCheckInterval) clearInterval(this.statusCheckInterval)

    // Remove event listeners
    const timerContainer = document.getElementById('navbar-timer-container')
    if (timerContainer) {
      timerContainer.removeEventListener('click', this.handleTimerClick)
    }

    const dropdownTimer = document.getElementById('dropdown-token-timer')
    if (dropdownTimer) {
      dropdownTimer.removeEventListener('click', this.handleTimerClick)
    }

    // Remove injected CSS
    const styles = document.getElementById('token-timer-styles')
    if (styles) {
      styles.remove()
    }

    console.log('TokenTimerManager destroyed')
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function () {
  // Create timer manager instance
  window.tokenTimer = new TokenTimerManager({
    // Custom options jika perlu
    expiredRedirectDelay: 600000, // 10 minutes
  })

  // Expose methods to global scope if needed
  window.refreshSession = () => window.tokenTimer.refreshSession()
  window.showSessionAlert = () => window.tokenTimer.showSessionAlert()
  window.showTokenInfo = () => window.tokenTimer.showTokenInfoPanel()
})
