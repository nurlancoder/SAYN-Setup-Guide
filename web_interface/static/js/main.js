let socket = null;
let currentScanId = null;
let scanProgress = 0;

document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});


function initializeApp() {
    initializeWebSocket();
    initializeEventListeners();
    initializeTooltips();
    initializeModals();
    initializeForms();
    
    console.log('SAYN Security Scanner initialized');
}


function initializeWebSocket() {
    try {
        socket = io();
        
        socket.on('connect', function() {
            console.log('Connected to SAYN Scanner');
            showNotification('Connected to scanner', 'success');
        });
        
        socket.on('disconnect', function() {
            console.log('Disconnected from scanner');
            showNotification('Disconnected from scanner', 'warning');
        });
        
        socket.on('scan_progress', function(data) {
            updateScanProgress(data);
        });
        
        socket.on('scan_completed', function(data) {
            handleScanCompleted(data);
        });
        
        socket.on('scan_error', function(data) {
            handleScanError(data);
        });
        
    } catch (error) {
        console.error('WebSocket initialization failed:', error);
    }
}


function initializeEventListeners() {
    const scanForm = document.getElementById('scan-config-form');
    if (scanForm) {
        scanForm.addEventListener('submit', handleScanSubmit);
    }
    
    const quickScanForm = document.getElementById('quick-scan-form');
    if (quickScanForm) {
        quickScanForm.addEventListener('submit', handleQuickScanSubmit);
    }
    
    document.querySelectorAll('.modal-close').forEach(button => {
        button.addEventListener('click', closeModal);
    });
    
    window.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal')) {
            closeModal(event.target);
        }
    });
    
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            closeAllModals();
        }
    });
}


function initializeTooltips() {
    const tooltipElements = document.querySelectorAll('[data-tooltip]');
    
    tooltipElements.forEach(element => {
        element.addEventListener('mouseenter', showTooltip);
        element.addEventListener('mouseleave', hideTooltip);
    });
}


function initializeModals() {
    document.querySelectorAll('[data-modal]').forEach(button => {
        button.addEventListener('click', function() {
            const modalId = this.getAttribute('data-modal');
            openModal(modalId);
        });
    });
}


function initializeForms() {
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', validateForm);
    });
    
    document.querySelectorAll('input, select, textarea').forEach(input => {
        input.addEventListener('change', autoSaveForm);
    });
}


async function handleScanSubmit(event) {
    event.preventDefault();
    
    const form = event.target;
    const formData = new FormData(form);
    
    if (!validateScanForm(formData)) {
        return;
    }
    
    const submitButton = form.querySelector('button[type="submit"]');
    const originalText = submitButton.textContent;
    submitButton.disabled = true;
    submitButton.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Starting Scan...';
    
    try {
        const scanData = {
            target: formData.get('target'),
            scan_name: formData.get('scan-name') || `Scan ${new Date().toLocaleString()}`,
            scan_type: getSelectedScanTypes(),
            scan_depth: formData.get('scan-depth') || 'normal',
            threads: parseInt(formData.get('threads')) || 10,
            timeout: parseInt(formData.get('timeout')) || 30
        };
        
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(scanData)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            currentScanId = result.scan_id;
            showScanProgress();
            showNotification('Scan started successfully', 'success');
        } else {
            throw new Error(result.error || 'Failed to start scan');
        }
        
    } catch (error) {
        console.error('Scan submission error:', error);
        showNotification(`Error: ${error.message}`, 'error');
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = originalText;
    }
}

async function handleQuickScanSubmit(event) {
    event.preventDefault();
    
    const form = event.target;
    const targetUrl = form.querySelector('#target-url').value;
    
    if (!targetUrl) {
        showNotification('Please enter a target URL', 'error');
        return;
    }
    
    const scanData = {
        target: targetUrl,
        scan_type: 'web',
        scan_depth: 'quick',
        threads: 5,
        timeout: 15
    };
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(scanData)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            currentScanId = result.scan_id;
            showNotification('Quick scan started', 'success');
            window.location.href = `/scan/${result.scan_id}`;
        } else {
            throw new Error(result.error || 'Failed to start scan');
        }
        
    } catch (error) {
        console.error('Quick scan error:', error);
        showNotification(`Error: ${error.message}`, 'error');
    }
}


function getSelectedScanTypes() {
    const checkboxes = document.querySelectorAll('input[name="scan-type"]:checked');
    return Array.from(checkboxes).map(cb => cb.value).join(',');
}


function validateScanForm(formData) {
    const target = formData.get('target');
    
    if (!target) {
        showNotification('Target URL is required', 'error');
        return false;
    }
    
    try {
        new URL(target);
    } catch (error) {
        showNotification('Please enter a valid URL', 'error');
        return false;
    }
    
    return true;
}


function showScanProgress() {
    const progressSection = document.getElementById('scan-progress');
    if (progressSection) {
        progressSection.classList.remove('hidden');
        progressSection.scrollIntoView({ behavior: 'smooth' });
    }
}


function updateScanProgress(data) {
    const progressBar = document.getElementById('progress-bar');
    const progressPercent = document.getElementById('progress-percent');
    const currentModule = document.getElementById('current-module');
    
    if (progressBar && progressPercent) {
        const progress = data.progress || 0;
        progressBar.style.width = `${progress}%`;
        progressPercent.textContent = `${progress}%`;
        
        if (progress === 100) {
            progressBar.className = 'bg-green-600 h-2.5 rounded-full';
        } else if (progress > 50) {
            progressBar.className = 'bg-blue-600 h-2.5 rounded-full';
        }
    }
    
    if (currentModule && data.message) {
        currentModule.textContent = data.message;
    }
    
    if (data.modules) {
        updateModuleStatus(data.modules);
    }
}


function updateModuleStatus(modules) {
    modules.forEach((module, index) => {
        const moduleElement = document.querySelector(`#modules-list li:nth-child(${index + 1}) div:first-child i`);
        if (moduleElement) {
            const iconClass = getModuleStatusIcon(module.status);
            moduleElement.className = iconClass;
        }
    });
}


function getModuleStatusIcon(status) {
    switch (status) {
        case 'completed':
            return 'fas fa-check-circle text-green-500';
        case 'running':
            return 'fas fa-spinner text-blue-500 animate-spin';
        case 'failed':
            return 'fas fa-times-circle text-red-500';
        default:
            return 'fas fa-circle-notch text-gray-300';
    }
}


function handleScanCompleted(data) {
    showNotification('Scan completed successfully!', 'success');
    
    updateScanProgress({ progress: 100, message: 'Scan completed!' });
    
    const resultsButton = document.createElement('a');
    resultsButton.href = `/scan/${data.scan_id}`;
    resultsButton.className = 'btn btn-primary mt-4';
    resultsButton.innerHTML = '<i class="fas fa-chart-bar mr-2"></i>View Results';
    
    const progressSection = document.getElementById('scan-progress');
    if (progressSection) {
        progressSection.appendChild(resultsButton);
    }
    
    if (window.location.pathname === '/') {
        setTimeout(() => {
            window.location.reload();
        }, 2000);
    }
}


function handleScanError(data) {
    showNotification(`Scan failed: ${data.error}`, 'error');
    
    updateScanProgress({ progress: 0, message: 'Scan failed' });
    
    const retryButton = document.createElement('button');
    retryButton.className = 'btn btn-secondary mt-4';
    retryButton.innerHTML = '<i class="fas fa-redo mr-2"></i>Retry Scan';
    retryButton.onclick = () => window.location.reload();
    
    const progressSection = document.getElementById('scan-progress');
    if (progressSection) {
        progressSection.appendChild(retryButton);
    }
}


function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 z-50 p-4 rounded-lg shadow-lg border-l-4 max-w-sm transition-all duration-300 transform translate-x-full`;
    
    const styles = {
        success: 'bg-green-50 border-green-500 text-green-700',
        error: 'bg-red-50 border-red-500 text-red-700',
        warning: 'bg-yellow-50 border-yellow-500 text-yellow-700',
        info: 'bg-blue-50 border-blue-500 text-blue-700'
    };
    
    notification.className += ` ${styles[type] || styles.info}`;
    
    const icon = {
        success: 'fas fa-check-circle',
        error: 'fas fa-exclamation-circle',
        warning: 'fas fa-exclamation-triangle',
        info: 'fas fa-info-circle'
    }[type];
    
    notification.innerHTML = `
        <div class="flex items-start">
            <div class="flex-shrink-0">
                <i class="${icon} text-xl"></i>
            </div>
            <div class="ml-3">
                <p class="text-sm font-medium">${message}</p>
            </div>
            <div class="ml-auto pl-3">
                <button class="text-gray-400 hover:text-gray-600" onclick="this.parentElement.parentElement.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.remove('translate-x-full');
    }, 100);
    
    setTimeout(() => {
        notification.classList.add('translate-x-full');
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 300);
    }, 5000);
}


function showTooltip(event) {
    const tooltipText = this.getAttribute('data-tooltip');
    const tooltip = document.createElement('div');
    
    tooltip.className = 'absolute z-10 p-2 text-xs text-white bg-gray-800 rounded shadow-lg';
    tooltip.textContent = tooltipText;
    tooltip.style.top = `${this.offsetTop - 30}px`;
    tooltip.style.left = `${this.offsetLeft + this.offsetWidth / 2}px`;
    tooltip.style.transform = 'translateX(-50%)';
    
    this.appendChild(tooltip);
    
    const rect = tooltip.getBoundingClientRect();
    if (rect.right > window.innerWidth) {
        tooltip.style.left = `${window.innerWidth - rect.width - 10}px`;
        tooltip.style.transform = 'none';
    }
    if (rect.left < 0) {
        tooltip.style.left = '10px';
        tooltip.style.transform = 'none';
    }
}


function hideTooltip() {
    const tooltip = this.querySelector('div[class*="absolute z-10"]');
    if (tooltip) {
        this.removeChild(tooltip);
    }
}


function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
        
        const firstInput = modal.querySelector('input, select, textarea');
        if (firstInput) {
            firstInput.focus();
        }
    }
}


function closeModal(modal) {
    if (typeof modal === 'string') {
        modal = document.getElementById(modal);
    }
    
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
    }
}


function closeAllModals() {
    document.querySelectorAll('.modal').forEach(modal => {
        closeModal(modal);
    });
}


function validateForm(event) {
    const form = event.target;
    const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
    let isValid = true;
    
    inputs.forEach(input => {
        if (!input.value.trim()) {
            input.classList.add('border-red-500');
            isValid = false;
        } else {
            input.classList.remove('border-red-500');
        }
    });
    
    if (!isValid) {
        event.preventDefault();
        showNotification('Please fill in all required fields', 'error');
    }
    
    return isValid;
}


function autoSaveForm(event) {
    const input = event.target;
    const form = input.closest('form');
    
    if (form) {
        const formData = new FormData(form);
        const formId = form.id || 'default';
        
        const data = {};
        for (let [key, value] of formData.entries()) {
            data[key] = value;
        }
        
        localStorage.setItem(`sayn_form_${formId}`, JSON.stringify(data));
    }
}


function loadSavedFormData(formId = 'default') {
    const savedData = localStorage.getItem(`sayn_form_${formId}`);
    
    if (savedData) {
        const data = JSON.parse(savedData);
        const form = document.getElementById(formId);
        
        if (form) {
            Object.keys(data).forEach(key => {
                const input = form.querySelector(`[name="${key}"]`);
                if (input) {
                    input.value = data[key];
                }
            });
        }
    }
}


function exportToCSV(data, filename) {
    const csvContent = convertToCSV(data);
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    
    if (link.download !== undefined) {
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', filename);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
}


function convertToCSV(data) {
    if (!data || data.length === 0) return '';
    
    const headers = Object.keys(data[0]);
    const csvRows = [headers.join(',')];
    
    data.forEach(row => {
        const values = headers.map(header => {
            const value = row[header] || '';
            return `"${value.toString().replace(/"/g, '""')}"`;
        });
        csvRows.push(values.join(','));
    });
    
    return csvRows.join('\n');
}


function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}


function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}


function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}


function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('form').forEach(form => {
        const formId = form.id || 'default';
        loadSavedFormData(formId);
    });
});

window.SAYN = {
    showNotification,
    openModal,
    closeModal,
    exportToCSV,
    formatDate,
    formatFileSize
};
