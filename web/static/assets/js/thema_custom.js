document.addEventListener('DOMContentLoaded', function () {
  const coreCss = document.querySelector('.template-customizer-core-css');
  const themeCss = document.querySelector('.template-customizer-theme-css');
  const html = document.documentElement;

  // Fungsi untuk set style
  function applyTheme(styleMode, themeType) {
    let coreFile = 'core.css';
    let themeFile = `theme-${themeType}.css`;

    if (styleMode === 'dark') {
      coreFile = 'core-dark.css';
      themeFile = `theme-${themeType}-dark.css`;
    } else if (styleMode === 'system') {
      // Jika system, sesuaikan dengan preferensi sistem
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      coreFile = prefersDark ? 'core-dark.css' : 'core.css';
      themeFile = prefersDark ? `theme-${themeType}-dark.css` : `theme-${themeType}.css`;
    }

    // Ganti href secara dinamis
    coreCss.href = `${html.dataset.assetsPath}vendor/css/${coreFile}`;
    themeCss.href = `${html.dataset.assetsPath}vendor/css/${themeFile}`;

    // Simpan preferensi ke localStorage
    localStorage.setItem('styleMode', styleMode);
    localStorage.setItem('themeType', themeType);

    // Update atribut HTML
    html.classList.remove('light-style', 'dark-style');
    html.removeAttribute('data-theme');
    html.classList.add(styleMode === 'dark' ? 'dark-style' : 'light-style');
    html.setAttribute('data-theme', `theme-${themeType}`);
  }

  // Muat preferensi dari localStorage
  const savedStyleMode = localStorage.getItem('styleMode') || 'light';
  const savedThemeType = localStorage.getItem('themeType') || 'default';
  applyTheme(savedStyleMode, savedThemeType);

  // Update radio button sesuai simpanan
  document.querySelector(`input[name="styleMode"][value="${savedStyleMode}"]`).checked = true;
  document.querySelector(`input[name="themeType"][value="${savedThemeType}"]`).checked = true;

  // Event listener untuk perubahan
  document.querySelectorAll('input[name="styleMode"]').forEach(el => {
    el.addEventListener('change', e => {
      applyTheme(e.target.value, localStorage.getItem('themeType') || 'default');
    });
  });

  document.querySelectorAll('input[name="themeType"]').forEach(el => {
    el.addEventListener('change', e => {
      applyTheme(localStorage.getItem('styleMode') || 'light', e.target.value);
    });
  });
});