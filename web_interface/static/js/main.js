/**
 * SAYN Security Scanner - Main JavaScript
 * Enhanced web interface functionality
 */

// Global variables
let currentScanId = null;
let scanProgressInterval = null;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeSocketIO();
    initializeEventListeners();
    initializeTooltips();
    initializeNotifications();
});

/**
 * Initialize SocketIO connection
 */
function initializeSocketIO() {
    if (typeof io !== 'undefined') {
        const socket = io();
        
        socket.on('connect', function() {
            console.log('Connected to SAYN Scanner');
            showNotification('Connected to scanner', 'success');
        });
        
        socket.on('disconnect', function() {
            console.log('Disconnected from SAYN Scanner');
            showNotification('Disconnected from scanner', 'warning');
        });
        
        socket.on('scan_completed', function(data) {
            handleScanCompleted(data);
        });
        
        socket.on('scan_error', function(data) {
            handleScanError(data);
        });
        
        socket.on('scan_progress', function(data) {
            updateScanProgress(data);
        });
        
        // Store socket globally
        window.saynSocket = socket;
    }
}

/**
 * Initialize event listeners
 */
function initializeEventListeners() {
    // Scan form submission
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', handleScanSubmit);
    }
    
    // Quick scan buttons
    const quickScanButtons = document.querySelectorAll('.quick-scan-btn');
    quickScanButtons.forEach(button => {
        button.addEventListener('click', handleQuickScan);
    });
    
    // Scan type selection
    const scanTypeSelect = document.getElementById('scan-type');
    if (scanTypeSelect) {
        scanTypeSelect.addEventListener('change', handleScanTypeChange);
    }
    
    // Scan depth selection
    const scanDepthSelect = document.getElementById('scan-depth');
    if (scanDepthSelect) {
        scanDepthSelect.addEventListener('change', handleScanDepthChange);
    }
    
    // Modal close buttons
    const modalCloseButtons = document.querySelectorAll('.modal-close, .modal-overlay');
    modalCloseButtons.forEach(button => {
        button.addEventListener('click', closeModal);
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);
}

/**
 * Handle scan form submission
 */
function handleScanSubmit(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const scanData = {
        target: formData.get('target'),
        scan_name: formData.get('scan_name') || `Scan - ${formData.get('target')}`,
        scan_type: formData.get('scan_type'),
        scan_depth: formData.get('scan_depth'),
        threads: parseInt(formData.get('threads')) || 10,
        timeout: parseInt(formData.get('timeout')) || 30
    };
    
    if (!scanData.target) {
        showNotification('Target URL is required', 'error');
        return;
    }
    
    startScan(scanData);
}

/**
 * Handle quick scan button clicks
 */
function handleQuickScan(event) {
    event.preventDefault();
    
    const button = event.currentTarget;
    const target = button.dataset.target;
    const scanType = button.dataset.scanType || 'web';
    
    const scanData = {
        target: target,
        scan_name: `Quick ${scanType.charAt(0).toUpperCase() + scanType.slice(1)} Scan - ${target}`,
        scan_type: scanType,
        scan_depth: 'normal',
        threads: 10,
        timeout: 30
    };
    
    startScan(scanData);
}

/**
 * Start a new scan
 */
function startScan(scanData) {
    showScanProgressModal();
    
    fetch('/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(scanData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.scan_id) {
            currentScanId = data.scan_id;
            showNotification('Scan started successfully', 'success');
            monitorScanProgress(data.scan_id);
        } else {
            showNotification('Error starting scan: ' + (data.error || 'Unknown error'), 'error');
            hideScanProgressModal();
        }
    })
    .catch(error => {
        console.error('Error starting scan:', error);
        showNotification('Error starting scan', 'error');
        hideScanProgressModal();
    });
}

/**
 * Monitor scan progress
 */
function monitorScanProgress(scanId) {
    if (scanProgressInterval) {
        clearInterval(scanProgressInterval);
    }
    
    scanProgressInterval = setInterval(() => {
        fetch(`/api/scan/${scanId}/progress`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    console.error('Error getting scan progress:', data.error);
                    return;
                }
                
                updateProgressUI(data);
                
                if (data.status === 'completed' || data.status === 'failed') {
                    clearInterval(scanProgressInterval);
                    scanProgressInterval = null;
                    
                    if (data.status === 'completed') {
                        showNotification('Scan completed successfully!', 'success');
                        setTimeout(() => {
                            hideScanProgressModal();
                            window.location.href = `/scan/${scanId}`;
                        }, 2000);
                    } else {
                        showNotification('Scan failed', 'error');
                        hideScanProgressModal();
                    }
                }
            })
            .catch(error => {
                console.error('Error monitoring scan progress:', error);
            });
    }, 2000);
}

/**
 * Update progress UI
 */
function updateProgressUI(data) {
    const progressBar = document.getElementById('scan-progress-bar');
    const progressText = document.getElementById('scan-progress-text');
    const modulesStatus = document.getElementById('scan-modules-status');
    
    if (progressBar) {
        const progress = data.progress || 0;
        progressBar.style.width = `${progress}%`;
        progressBar.setAttribute('aria-valuenow', progress);
    }
    
    if (progressText) {
        progressText.textContent = data.status || 'Scanning...';
    }
    
    if (modulesStatus && data.modules) {
        modulesStatus.innerHTML = Object.entries(data.modules).map(([module, status]) => `
            <div class="flex items-center justify-between text-sm">
                <span class="text-gray-600">${module}</span>
                <span class="inline-flex items-center">
                    ${getModuleStatusIcon(status)}
                    <span class="ml-1 text-gray-500">${status}</span>
                </span>
            </div>
        `).join('');
    }
}

/**
 * Handle scan completion
 */
function handleScanCompleted(data) {
    if (data.scan_id === currentScanId) {
        showNotification('Scan completed successfully!', 'success');
        setTimeout(() => {
            hideScanProgressModal();
            window.location.href = `/scan/${data.scan_id}`;
        }, 2000);
    }
}

/**
 * Handle scan error
 */
function handleScanError(data) {
    if (data.scan_id === currentScanId) {
        showNotification('Scan failed: ' + data.error, 'error');
        hideScanProgressModal();
    }
}

/**
 * Update scan progress from SocketIO
 */
function updateScanProgress(data) {
    if (data.scan_id === currentScanId) {
        updateProgressUI(data);
    }
}

/**
 * Show scan progress modal
 */
function showScanProgressModal() {
    const modal = document.getElementById('scan-progress-modal');
    if (modal) {
        modal.classList.remove('hidden');
        document.body.classList.add('overflow-hidden');
    }
}

/**
 * Hide scan progress modal
 */
function hideScanProgressModal() {
    const modal = document.getElementById('scan-progress-modal');
    if (modal) {
        modal.classList.add('hidden');
        document.body.classList.remove('overflow-hidden');
    }
}

/**
 * Close modal
 */
function closeModal() {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        modal.classList.add('hidden');
    });
    document.body.classList.remove('overflow-hidden');
}

/**
 * Show notification
 */
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 z-50 p-4 rounded-lg shadow-lg transition-all duration-300 transform translate-x-full ${getNotificationClass(type)}`;
    notification.innerHTML = `
        <div class="flex items-center">
            ${getNotificationIcon(type)}
            <span class="ml-2">${message}</span>
            <button class="ml-4 text-white hover:text-gray-200" onclick="this.parentElement.parentElement.remove()">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                </svg>
            </button>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.classList.remove('translate-x-full');
    }, 100);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        notification.classList.add('translate-x-full');
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 300);
    }, 5000);
}

/**
 * Get notification CSS class
 */
function getNotificationClass(type) {
    switch (type) {
        case 'success':
            return 'bg-green-500 text-white';
        case 'error':
            return 'bg-red-500 text-white';
        case 'warning':
            return 'bg-yellow-500 text-white';
        case 'info':
        default:
            return 'bg-blue-500 text-white';
    }
}

/**
 * Get notification icon
 */
function getNotificationIcon(type) {
    switch (type) {
        case 'success':
            return '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>';
        case 'error':
            return '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>';
        case 'warning':
            return '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path></svg>';
        case 'info':
        default:
            return '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';
    }
}

/**
 * Get module status icon
 */
function getModuleStatusIcon(status) {
    switch (status.toLowerCase()) {
        case 'completed':
            return '<svg class="w-4 h-4 text-green-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path></svg>';
        case 'running':
            return '<svg class="w-4 h-4 text-blue-500 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>';
        case 'failed':
            return '<svg class="w-4 h-4 text-red-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path></svg>';
        default:
            return '<svg class="w-4 h-4 text-gray-400" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd"></path></svg>';
    }
}

/**
 * Handle keyboard shortcuts
 */
function handleKeyboardShortcuts(event) {
    // Ctrl/Cmd + N for new scan
    if ((event.ctrlKey || event.metaKey) && event.key === 'n') {
        event.preventDefault();
        window.location.href = '/scan';
    }
    
    // Ctrl/Cmd + H for history
    if ((event.ctrlKey || event.metaKey) && event.key === 'h') {
        event.preventDefault();
        window.location.href = '/history';
    }
    
    // Escape to close modals
    if (event.key === 'Escape') {
        closeModal();
    }
}

/**
 * Initialize tooltips
 */
function initializeTooltips() {
    const tooltipElements = document.querySelectorAll('[data-tooltip]');
    tooltipElements.forEach(element => {
        element.addEventListener('mouseenter', showTooltip);
        element.addEventListener('mouseleave', hideTooltip);
    });
}

/**
 * Show tooltip
 */
function showTooltip(event) {
    const element = event.target;
    const tooltipText = element.getAttribute('data-tooltip');
    
    const tooltip = document.createElement('div');
    tooltip.className = 'absolute z-50 px-2 py-1 text-sm text-white bg-gray-900 rounded shadow-lg';
    tooltip.textContent = tooltipText;
    tooltip.id = 'tooltip';
    
    document.body.appendChild(tooltip);
    
    const rect = element.getBoundingClientRect();
    tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
    tooltip.style.top = rect.top - tooltip.offsetHeight - 5 + 'px';
}

/**
 * Hide tooltip
 */
function hideTooltip() {
    const tooltip = document.getElementById('tooltip');
    if (tooltip) {
        tooltip.remove();
    }
}

/**
 * Initialize notifications
 */
function initializeNotifications() {
    // Check for existing notifications and remove them
    const existingNotifications = document.querySelectorAll('.notification');
    existingNotifications.forEach(notification => {
        setTimeout(() => {
            notification.remove();
        }, 5000);
    });
}

/**
 * Format date
 */
function formatDate(dateString) {
    if (!dateString) return 'Unknown';
    
    const date = new Date(dateString);
    const now = new Date();
    const diffInHours = (now - date) / (1000 * 60 * 60);
    
    if (diffInHours < 1) {
        return 'Just now';
    } else if (diffInHours < 24) {
        return `${Math.floor(diffInHours)} hours ago`;
    } else {
        return date.toLocaleDateString();
    }
}

/**
 * Format file size
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Copy to clipboard
 */
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showNotification('Copied to clipboard', 'success');
    }).catch(() => {
        showNotification('Failed to copy to clipboard', 'error');
    });
}

/**
 * Export data
 */
function exportData(data, filename, type = 'json') {
    let content, mimeType;
    
    if (type === 'json') {
        content = JSON.stringify(data, null, 2);
        mimeType = 'application/json';
    } else if (type === 'csv') {
        content = convertToCSV(data);
        mimeType = 'text/csv';
    }
    
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showNotification('Data exported successfully', 'success');
}

/**
 * Convert data to CSV
 */
function convertToCSV(data) {
    if (!Array.isArray(data) || data.length === 0) return '';
    
    const headers = Object.keys(data[0]);
    const csvContent = [
        headers.join(','),
        ...data.map(row => headers.map(header => `"${row[header] || ''}"`).join(','))
    ].join('\n');
    
    return csvContent;
}

// Export functions for global use
window.showNotification = showNotification;
window.formatDate = formatDate;
window.formatFileSize = formatFileSize;
window.copyToClipboard = copyToClipboard;
window.exportData = exportData;
