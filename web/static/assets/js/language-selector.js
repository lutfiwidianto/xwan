// file: static/js/language-switcher.js (versi minimal)
document.addEventListener('DOMContentLoaded', function() {
    const languageItems = document.querySelectorAll('.language-item');
    
    languageItems.forEach(item => {
        item.addEventListener('click', async function(e) {
            e.preventDefault();
            
            if (this.classList.contains('active')) return;
            
            const langCode = this.getAttribute('data-lang-code');
            const previousActive = document.querySelector('.language-item.active');
            
            // Update UI optimistically
            if (previousActive) {
                previousActive.classList.remove('active');
                const prevIcon = previousActive.querySelector('.bx-check');
                if (prevIcon) prevIcon.classList.add('d-none');
            }
            
            this.classList.add('active');
            const currentIcon = this.querySelector('.bx-check');
            if (currentIcon) currentIcon.classList.remove('d-none');
            
            try {
                const response = await fetch('/api/update-language', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ lang_code: langCode })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    // Langsung reload jika sukses
                    window.location.reload();
                } else {
                    // Rollback jika gagal
                    if (previousActive) {
                        languageItems.forEach(el => {
                            el.classList.remove('active');
                            const icon = el.querySelector('.bx-check');
                            if (icon) icon.classList.add('d-none');
                        });
                        previousActive.classList.add('active');
                        const prevIcon = previousActive.querySelector('.bx-check');
                        if (prevIcon) prevIcon.classList.remove('d-none');
                    }
                }
                
            } catch (error) {
                // Rollback jika error network
                if (previousActive) {
                    languageItems.forEach(el => {
                        el.classList.remove('active');
                        const icon = el.querySelector('.bx-check');
                        if (icon) icon.classList.add('d-none');
                    });
                    previousActive.classList.add('active');
                    const prevIcon = previousActive.querySelector('.bx-check');
                    if (prevIcon) prevIcon.classList.remove('d-none');
                }
            }
        });
    });
});