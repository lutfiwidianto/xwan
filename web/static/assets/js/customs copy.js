// ======================
// CUSTOM THEME & LAYOUT
// ======================
document.addEventListener('DOMContentLoaded', function () { // --- LOGIKA THEME SETTINGS ---
    const KEY_STYLE = 'frest-custom-style';
    const KEY_THEME = 'frest-custom-theme';
    const PATH = '/static/assets/vendor/css/';
    const STORAGE_KEY_LAYOUT = 'my_custom_layout_preference';

    function applyTheme(themeName, styleMode) {
        const coreCss = document.getElementById('core-css');
        const themeCss = document.getElementById('theme-css');

        if (! coreCss || ! themeCss) 
            return;
        

        const suffix = styleMode === 'dark' ? '-dark' : '';
        coreCss.href = `${PATH}core${suffix}.css`;
        themeCss.href = `${PATH}${themeName}${suffix}.css`;
    }

    function applyCheckedRadios(style, theme) {
        const styleRadio = document.querySelector(`input[name="styleMode"][value="${style}"]`);
        if (styleRadio) 
            styleRadio.checked = true;
        

        const themeShort = theme.replace('theme-', '');
        const themeRadio = document.querySelector(`input[name="themeType"][value="${themeShort}"]`);
        if (themeRadio) 
            themeRadio.checked = true;
        
    }

    function loadSettings() {
        const style = localStorage.getItem(KEY_STYLE) || 'light';
        const theme = localStorage.getItem(KEY_THEME) || 'theme-default';

        applyTheme(theme, style);
        applyCheckedRadios(style, theme);
    }

    loadSettings();

    document.querySelectorAll("input[name='styleMode']").forEach((el) => {
        el.addEventListener('change', function () {
            const style = this.value;
            localStorage.setItem(KEY_STYLE, style);

            const theme = localStorage.getItem(KEY_THEME);
            applyTheme(theme, style);
        });
    });

    document.querySelectorAll("input[name='themeType']").forEach((el) => {
        el.addEventListener('change', function () {
            const theme = 'theme-' + this.value;
            localStorage.setItem(KEY_THEME, theme);

            const style = localStorage.getItem(KEY_STYLE);
            applyTheme(theme, style);
        });
    });

    // --- LOGIKA LAYOUT WIDE/COMPACT SETTINGS ---
    const radioWide = document.getElementById('layoutWide');
    const radioCompact = document.getElementById('layoutCompact');

    window.setCustomLayout = function (mode) {
        if (mode === 'wide') {
            document.documentElement.classList.add('layout-wide');
        } else {
            document.documentElement.classList.remove('layout-wide');
        }

        localStorage.setItem(STORAGE_KEY_LAYOUT, mode);
        updateRadios(mode);
    };

    function updateRadios(mode) {
        if (mode === 'wide' && radioWide) 
            radioWide.checked = true;
        
        if (mode === 'compact' && radioCompact) 
            radioCompact.checked = true;
        
    }

    const savedLayout = localStorage.getItem(STORAGE_KEY_LAYOUT);

    if (savedLayout) {
        updateRadios(savedLayout);
    } else {
        updateRadios('wide');
    }
});

// ======================
// LOADER PROGRESS BAR
// ======================
window.addEventListener('load', function () {
    const progressBar = document.getElementById('progress-bar');

    if (progressBar) {
        setTimeout(function () { // Mulai fade-out
            progressBar.style.opacity = '50';

            // Hilangkan setelah transisi
            setTimeout(function () {
                progressBar.style.display = 'none';
            }, 300);
        }, 100);
    }
});
