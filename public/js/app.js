document.addEventListener("DOMContentLoaded", () => {
    // --- ELEMENTLER ---
    const modalOverlay = document.getElementById("auth-modal");
    const closeModalBtn = document.getElementById("close-modal-btn");
    const themeBtn = document.getElementById("theme-toggle");
    
    const sections = {
        upload: document.getElementById("upload-section"),
        result: document.getElementById("result-section")
    };
    
    const nav = {
        guest: document.getElementById("guest-nav"),
        user: document.getElementById("user-nav"),
        authBtn: document.getElementById("auth-trigger-btn"),
        logoutBtn: document.getElementById("logout-btn"),
        logoBtn: document.getElementById("logo-btn")
    };

    const formEls = {
        fileInput: document.getElementById("file"),
        dropZone: document.getElementById("drop-zone"),
        fileList: document.getElementById("file-list-container"),
        limitBadge: document.getElementById("limit-badge"),
        expirySelect: document.getElementById("expiry-duration"),
        maxViews: document.getElementById("max-views"),
        burnCheck: document.getElementById("burn-check"),
        requirePasswordCheck: document.getElementById("require-password-check"),
        passwordWrapper: document.getElementById("password-wrapper"),
        qrImage: document.getElementById("qr-image"),
        shareLink: document.getElementById("share-link")
    };

    const authTabs = {
        loginBtn: document.getElementById("tab-login"),
        registerBtn: document.getElementById("tab-register"),
        loginForm: document.getElementById("login-form"),
        registerForm: document.getElementById("register-form"),
        errorMsg: document.getElementById("auth-error-msg")
    };

    let selectedFiles = [];

    // --- 1. KARANLIK MOD ---
    themeBtn.addEventListener("click", () => {
        document.body.classList.toggle("dark-mode");
        const isDark = document.body.classList.contains("dark-mode");
        themeBtn.textContent = isDark ? "☀️" : "🌙";
    });

    // --- 2. GÜVENLİK ---
    // Yak seçeneği: işaretlenirse maxViews = 1 ve kilitlenir
    formEls.burnCheck.addEventListener("change", (e) => {
        if(e.target.checked) {
            formEls.maxViews.value = 1;
            formEls.maxViews.disabled = true; 
        } else {
            formEls.maxViews.disabled = false;
        }
    });

    // Parola zorunlu seçeneği: işaretlenirse parola alanı açılır
    if (formEls.requirePasswordCheck && formEls.passwordWrapper) {
        formEls.requirePasswordCheck.addEventListener("change", (e) => {
            if (e.target.checked) {
                formEls.passwordWrapper.style.display = 'block';
            } else {
                formEls.passwordWrapper.style.display = 'none';
                const pwInput = document.getElementById("password");
                if (pwInput) pwInput.value = '';
            }
        });
    }

    // --- 3. MODAL & AUTH ---
    const openModal = (mode = 'login') => {
        modalOverlay.style.display = 'flex';
        authTabs.errorMsg.textContent = "";
        if (mode === 'login') authTabs.loginBtn.click();
        else authTabs.registerBtn.click();
    };
    const closeModal = () => modalOverlay.style.display = 'none';

    nav.authBtn.addEventListener("click", () => openModal('login'));
    closeModalBtn.addEventListener("click", closeModal);
    modalOverlay.addEventListener("click", (e) => { if (e.target === modalOverlay) closeModal(); });

    authTabs.loginBtn.addEventListener("click", () => {
        authTabs.loginBtn.classList.add("active");
        authTabs.registerBtn.classList.remove("active");
        authTabs.loginForm.style.display = "block";
        authTabs.registerForm.style.display = "none";
        authTabs.errorMsg.textContent = "";
    });
    authTabs.registerBtn.addEventListener("click", () => {
        authTabs.registerBtn.classList.add("active");
        authTabs.loginBtn.classList.remove("active");
        authTabs.registerForm.style.display = "block";
        authTabs.loginForm.style.display = "none";
        authTabs.errorMsg.textContent = "";
    });

    // --- GİRİŞ & KAYIT MANTIĞI (DÜZELTİLDİ) ---

    let currentUser = null;

    // Kayıt Formu
    authTabs.registerForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const honeypot = document.getElementById("spam-trap").value;
        if (honeypot) return; 

        const pass = document.getElementById("reg-pass").value;
        const passConfirm = document.getElementById("reg-pass-confirm").value;
        const name = document.getElementById("reg-name").value;
        const email = document.getElementById("reg-email").value;

        if (pass.length < 6) { authTabs.errorMsg.textContent = "Şifre çok kısa."; return; }
        if (pass !== passConfirm) { authTabs.errorMsg.textContent = "Şifreler eşleşmiyor."; return; }

        try {
            const res = await fetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, email, password: pass })
            });
            const data = await res.json();

            if (res.ok) {
                currentUser = data.user;
                loginUser(currentUser.name);
                closeModal();
            } else {
                authTabs.errorMsg.textContent = data.error || "Kayıt başarısız.";
            }
        } catch (err) {
            authTabs.errorMsg.textContent = "Sunucu hatası.";
        }
    });

    // Giriş Formu
    authTabs.loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const email = authTabs.loginForm.querySelector('input[type="email"]').value;
        const password = authTabs.loginForm.querySelector('input[type="password"]').value;
        
        try {
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            const data = await res.json();

            if (res.ok) {
                currentUser = data.user;
                loginUser(currentUser.name);
                closeModal();
            } else {
                authTabs.errorMsg.textContent = data.error || "Giriş başarısız.";
            }
        } catch (err) {
            authTabs.errorMsg.textContent = "Sunucu hatası.";
        }
    });

    nav.logoutBtn.addEventListener("click", logoutUser);

    function loginUser(name) {
        nav.guest.style.display = "none";
        nav.user.style.display = "block";
        document.getElementById("user-name-display").textContent = name;
        formEls.limitBadge.textContent = "Limit: 100MB (Üye)";
        formEls.limitBadge.parentElement.parentElement.classList.add("premium-active");
        formEls.expirySelect.querySelector(".premium-option").disabled = false;
        formEls.expirySelect.querySelector(".premium-option").textContent = "7 Gün";
    }

    function logoutUser() {
        currentUser = null;
        nav.guest.style.display = "block";
        nav.user.style.display = "none";
        formEls.limitBadge.textContent = "Limit: 50MB";
        formEls.limitBadge.parentElement.parentElement.classList.remove("premium-active");
        const opt = formEls.expirySelect.querySelector(".premium-option");
        opt.disabled = true; opt.textContent = "7 Gün (Üye)";
        formEls.expirySelect.value = "1h";
    }

    // --- 4. DRAG & DROP & PASTE ---
    formEls.dropZone.addEventListener("click", () => formEls.fileInput.click());
    
    const handleFiles = (files) => {
        const newFiles = Array.from(files);
        selectedFiles = [...selectedFiles, ...newFiles];
        updateUI();
    };

    formEls.fileInput.addEventListener("change", (e) => handleFiles(e.target.files));

    formEls.dropZone.addEventListener("dragover", (e) => { e.preventDefault(); formEls.dropZone.classList.add("drag-over"); });
    formEls.dropZone.addEventListener("dragleave", () => formEls.dropZone.classList.remove("drag-over"));
    formEls.dropZone.addEventListener("drop", (e) => {
        e.preventDefault(); formEls.dropZone.classList.remove("drag-over");
        handleFiles(e.dataTransfer.files);
    });

    document.addEventListener('paste', (event) => {
        if (sections.upload.style.display === 'none') return; 
        const items = (event.clipboardData || event.originalEvent.clipboardData).items;
        for (let item of items) {
            if (item.kind === 'file') {
                const blob = item.getAsFile();
                handleFiles([blob]);
            }
        }
    });

    function updateUI() {
        formEls.fileList.innerHTML = "";
        selectedFiles.forEach((file, index) => {
            const li = document.createElement("li");
            li.className = "ts-file-item";

            const nameSpan = document.createElement("span");
            nameSpan.textContent = file.name; // XSS'e karşı güvenli

            const removeBtn = document.createElement("button");
            removeBtn.type = "button";
            removeBtn.className = "ts-remove-btn";
            removeBtn.dataset.idx = index;
            removeBtn.textContent = "×";

            li.appendChild(nameSpan);
            li.appendChild(removeBtn);
            formEls.fileList.appendChild(li);
        });
        document.querySelectorAll(".ts-remove-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                selectedFiles.splice(e.target.dataset.idx, 1);
                updateUI();
            });
        });
    }

    // --- 5. SİMÜLASYON ---
    document.getElementById("upload-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        if (!selectedFiles.length) {
            alert("Lütfen önce en az bir dosya ekleyin.");
            return;
        }
        
        const formData = new FormData();
        selectedFiles.forEach(file => formData.append('file[]', file));
        
        const passwordInput = document.getElementById("password");
        const passwordValue = passwordInput ? passwordInput.value : '';

        // Eğer "Parola zorunlu" işaretliyse ama şifre boşsa, engelle
        if (formEls.requirePasswordCheck && formEls.requirePasswordCheck.checked && !passwordValue.trim()) {
            alert("Lütfen bir parola belirleyin.");
            return;
        }

        formData.append('duration', formEls.expirySelect.value);
        formData.append('maxViews', formEls.maxViews.value);
        formData.append('password', passwordValue);
        // E2EE kaldırıldı; backend'e her zaman false gönderiyoruz (opsiyon devre dışı)
        formData.append('e2ee', false);
        formData.append('burn', formEls.burnCheck.checked);
        if (currentUser) {
            formData.append('ownerId', currentUser.id);
        }

        const progressFill = document.getElementById("progress-fill");
        document.getElementById("progress-container").style.display = "block";
        document.getElementById("upload-btn").disabled = true;
        document.getElementById("upload-btn").textContent = "Yükleniyor...";

        try {
            // Fake progress for UX
            let width = 0;
            const interval = setInterval(() => {
                if (width < 90) width += 5;
                progressFill.style.width = width + "%";
            }, 100);

            const res = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();

            clearInterval(interval);
            progressFill.style.width = "100%";

            if (res.ok) {
                setTimeout(() => {
                    sections.upload.style.display = 'none';
                    sections.result.style.display = 'block';
        
                    const resultContainer = document.querySelector('.ts-result-content');
                    const linkBox = document.querySelector('.ts-link-box');
                    const qrArea = document.querySelector('.ts-qr-area');
                    const newUploadBtn = document.getElementById("new-upload-btn");
        
                    // Önceki yüklemeden kalan listeyi temizle
                    const oldList = document.getElementById('multi-file-list');
                    if(oldList) oldList.remove();

                    if (data.files.length > 1) {
                        // ÇOKLU DOSYA DURUMU
                        linkBox.style.display = 'none';
                        qrArea.style.display = 'none';
            
                        let linksHtml = '<div id="multi-file-list" style="text-align: left; margin-bottom: 1.5rem;">';
                        linksHtml += '<h3 style="font-size: 1.1rem; margin-bottom: 1rem; color: var(--text-main);">Dosyalarınız Hazır:</h3>';
                        linksHtml += '<div style="max-height: 250px; overflow-y: auto; padding-right: 5px;">';
            
                        data.files.forEach(file => {
                            const finalLink = window.location.origin + "/download.html?token=" + file.token;
                            linksHtml += `
                                <div style="background: var(--bg-hover); padding: 10px; border-radius: 10px; margin-bottom: 8px; border: 1px solid var(--border-color);">
                                    <div style="font-size: 0.85rem; font-weight: 600; margin-bottom: 5px; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${file.filename}</div>
                                    <div style="display: flex; gap: 5px;">
                                        <input type="text" value="${finalLink}" readonly style="flex: 1; padding: 6px; font-size: 0.75rem; border: 1px solid var(--border-color); border-radius: 6px; background: var(--bg-card); color: var(--text-main);">
                                        <button type="button" onclick="navigator.clipboard.writeText('${finalLink}'); alert('Link Kopyalandı!');" class="ts-btn-icon" style="width: 34px; height: 34px; flex-shrink: 0;">📋</button>
                                    </div>
                                </div>`;
                        });
                        linksHtml += '</div></div>';
            
                        // Listeyi "Yeni Dosya Gönder" butonunun hemen üstüne ekle
                        newUploadBtn.insertAdjacentHTML('beforebegin', linksHtml);
            
                    } else {
                        // TEKLİ DOSYA DURUMU (Eski Düzen)
                        linkBox.style.display = 'flex';
                        qrArea.style.display = 'block';
            
                        const token = data.files[0].token;
                        const finalLink = window.location.origin + "/download.html?token=" + token;
            
                        formEls.shareLink.value = finalLink;
                        formEls.qrImage.src = `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${finalLink}`;
                    }
        
                    document.getElementById("upload-btn").disabled = false;
                    document.getElementById("upload-btn").textContent = "Link Oluştur";
                }, 500);
            }
            else {
                alert("Hata: " + (data.error || "Yükleme başarısız."));
                document.getElementById("upload-btn").disabled = false;
                document.getElementById("upload-btn").textContent = "Link Oluştur";
                document.getElementById("progress-container").style.display = 'none';
            }
        } catch (err) {
            alert("Sunucu hatası.");
            document.getElementById("upload-btn").disabled = false;
            document.getElementById("upload-btn").textContent = "Link Oluştur";
            document.getElementById("progress-container").style.display = 'none';
        }
    });

    document.getElementById("new-upload-btn").addEventListener("click", () => {
        sections.result.style.display = 'none';
        sections.upload.style.display = 'block';
        document.getElementById("progress-container").style.display = 'none';
        selectedFiles = [];
        updateUI();
    });

    document.getElementById("copy-btn").addEventListener("click", () => {
        formEls.shareLink.select();
        document.execCommand("copy");
    });
});
