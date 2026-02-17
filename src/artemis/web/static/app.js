// Project Artemis - Web UI JavaScript

let rulesGenerated = parseInt(localStorage.getItem('rulesGenerated') || '0');

const modelsByProvider = {
    ollama: ['qwen3:14b', 'qwen3:32b', 'deepseek-r1:70b'],
    anthropic: ['claude-sonnet-4-20250514'],
    openai: ['gpt-4o'],
};

const formatLangs = {
    sigma: 'yaml',
    yara: 'yara',
    splunk: 'spl',
    kql: 'kql',
    snort: 'snort',
};

function updateModels() {
    const provider = document.getElementById('provider').value;
    const modelSelect = document.getElementById('model');
    const models = modelsByProvider[provider] || [];
    
    modelSelect.innerHTML = '';
    models.forEach((model, index) => {
        const option = document.createElement('option');
        option.value = model;
        option.textContent = model;
        if (index === 0) option.selected = true;
        modelSelect.appendChild(option);
    });
}

function focusDescription() {
    document.getElementById('description').focus();
}

async function generateRule() {
    const btn = document.getElementById('generateBtn');
    const btnText = btn.querySelector('.btn-text');
    const btnLoading = btn.querySelector('.btn-loading');
    
    const description = document.getElementById('description').value.trim();
    if (!description) {
        alert('Please enter a threat description');
        return;
    }
    
    const format = document.getElementById('format').value;
    const provider = document.getElementById('provider').value;
    const model = document.getElementById('model').value;
    const severity = document.getElementById('severity').value;
    const context = document.getElementById('context').value.trim();
    const indicatorsRaw = document.getElementById('indicators').value.trim();
    const indicators = indicatorsRaw ? indicatorsRaw.split(',').map(i => i.trim()) : null;
    
    // Update UI
    btn.disabled = true;
    btnText.style.display = 'none';
    btnLoading.style.display = 'inline';
    
    document.getElementById('outputSection').classList.add('hidden');
    document.getElementById('errorSection').classList.add('hidden');
    
    try {
        const response = await fetch('/api/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                description,
                format,
                provider,
                model,
                severity: severity || null,
                context: context || null,
                indicators,
            }),
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayResult(data);
        } else {
            displayError(data.error || 'Unknown error occurred');
        }
    } catch (error) {
        displayError(`Network error: ${error.message}`);
    } finally {
        btn.disabled = false;
        btnText.style.display = 'inline';
        btnLoading.style.display = 'none';
    }
}

function displayResult(data) {
    // Increment counter
    rulesGenerated++;
    localStorage.setItem('rulesGenerated', rulesGenerated.toString());
    document.getElementById('rulesGenerated').textContent = rulesGenerated;
    
    // Rule name
    document.getElementById('ruleName').textContent = data.rule_name || 'Generated Rule';
    
    // Format badge
    const formatBadge = document.getElementById('formatBadge');
    formatBadge.textContent = (data.format || 'sigma').toUpperCase();
    
    // Severity badge
    const severityBadge = document.getElementById('severityBadge');
    const severity = data.severity || 'medium';
    severityBadge.textContent = severity.toUpperCase();
    severityBadge.className = `badge badge-severity ${severity}`;
    
    // Valid badge
    const validBadge = document.getElementById('validBadge');
    validBadge.textContent = data.is_valid ? 'VALID' : 'INVALID';
    validBadge.className = `badge ${data.is_valid ? 'badge-valid' : 'badge-invalid'}`;
    
    // Info
    document.getElementById('modelUsed').textContent = data.model_used || '-';
    document.getElementById('genTime').textContent = data.generation_time_ms 
        ? `${(data.generation_time_ms / 1000).toFixed(1)}s` 
        : '-';
    
    // Code language
    document.getElementById('codeLang').textContent = formatLangs[data.format] || 'text';
    
    // MITRE
    const mitreContainer = document.getElementById('mitreContainer');
    if (data.mitre && data.mitre.length > 0) {
        const techniques = data.mitre.map(m => m.subtechnique_id || m.technique_id).join(', ');
        document.getElementById('mitreMapping').textContent = techniques;
        mitreContainer.style.display = 'block';
    } else {
        mitreContainer.style.display = 'none';
    }
    
    // Validation errors
    const validationErrors = document.getElementById('validationErrors');
    if (data.validation_errors && data.validation_errors.length > 0) {
        document.getElementById('errorsList').innerHTML = 
            data.validation_errors.map(e => `<li>${escapeHtml(e)}</li>`).join('');
        validationErrors.classList.remove('hidden');
    } else {
        validationErrors.classList.add('hidden');
    }
    
    // Rule content
    document.getElementById('ruleContent').textContent = data.rule_content || '';
    
    // Show section
    document.getElementById('outputSection').classList.remove('hidden');
    document.getElementById('outputSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function displayError(message) {
    document.getElementById('errorMessage').textContent = message;
    document.getElementById('errorSection').classList.remove('hidden');
    document.getElementById('errorSection').scrollIntoView({ behavior: 'smooth' });
}

function copyRule() {
    const content = document.getElementById('ruleContent').textContent;
    navigator.clipboard.writeText(content).then(() => {
        const btn = document.querySelector('.copy-btn');
        const original = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = original, 2000);
    }).catch(err => {
        console.error('Copy failed:', err);
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    updateModels();
    document.getElementById('rulesGenerated').textContent = rulesGenerated;
    
    // Ctrl+Enter to submit
    document.getElementById('description').addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key === 'Enter') {
            generateRule();
        }
    });
});
