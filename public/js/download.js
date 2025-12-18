document.addEventListener("DOMContentLoaded", () => {
    // --- ELEMENTLER ---
    const themeBtn = document.getElementById("theme-toggle");
    const downloadBtn = document.getElementById("download-btn");
    const passwordSection = document.getElementById("password-section");
    const lockBadge = document.getElementById("lock-badge");
    const passwordInput = document.getElementById("file-password");
    const errorText = document.getElementById("password-error");
    const fileNameDisplay = document.getElementById("file-name");

    // Rapor Modalı Elementleri
    const reportLink = document.getElementById("report-link");
    const reportModal = document.getElementById("report-modal");
    const closeReportBtn = document.getElementById("close-report-btn");
    const reportForm = document.getElementById("report-form");

    // --- 1. TEMA AYARI ---
    if (themeBtn) {
        // Daha önce kaydedilmiş tema var mı kontrol et
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'dark') {
            document.body.classList.add('dark-mode');
            themeBtn.textContent = "☀️";
        }

        themeBtn.addEventListener("click", () => {
            document.body.classList.toggle("dark-mode");
            const isDark = document.body.classList.contains("dark-mode");
            
            // İkonu değiştir
            themeBtn.textContent = isDark ? "☀️" : "🌙";
            
            // Tercihi tarayıcıya kaydet (Sayfa yenilenince gitmesin)
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
        });
    }

    // İndirme öncesi metadata'yı sakla (limit kontrolü için)
    let currentFileMetadata = null;

    // --- 2. DURUM SİMÜLASYONU ---
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    
    if (!token) {
        alert("Geçersiz link.");
        return;
    }

    // Fetch File Metadata
    fetch(`/api/files/${token}`)
        .then(res => {
            if (res.status === 404) throw new Error("Dosya bulunamadı.");
            if (!res.ok) throw new Error("Sunucu hatası.");
            return res.json();
        })
        .then(data => {
            // Metadata'yı sakla (indirme sonrası limit kontrolü için)
            currentFileMetadata = data;
            
            if(fileNameDisplay) fileNameDisplay.textContent = data.filename;
            
            // Update Meta
            const metaDiv = document.querySelector(".ts-file-meta");
            if (metaDiv) {
                const sizeMB = (data.size / (1024 * 1024)).toFixed(2);
                const timeLeft = Math.max(0, Math.ceil((data.expiresAt - Date.now()) / (1000 * 60 * 60)));
                
                metaDiv.innerHTML = `
                    <span>💾 ${sizeMB} MB</span>
                    <span class="ts-dot">•</span>
                    <span>👤 Yükleyen: ${data.owner}</span>
                    <span class="ts-dot">•</span>
                    <span>⏳ ${timeLeft} Saat Kaldı</span>
                `;
            }

            // İndirme limiti veya süre kontrolü - öncelik limit
            // Değerleri sayıya çevir (güvenli kontrol)
            const downloadCount = Number(data.downloadCount) || 0;
            const downloadLimit = Number(data.downloadLimit) || 1;
            const isLimitReached = data.isLimitReached === true || downloadCount >= downloadLimit;
            const isExpired = data.isExpired === true || (Date.now() > Number(data.expiresAt));
            
            // ÖNEMLİ: Limit kontrolü en önce yapılmalı, şifre korumalı olsa bile
            if (isLimitReached) {
                // Limit dolmuş - butonu devre dışı bırak ve mesaj göster
                downloadBtn.disabled = true;
                downloadBtn.innerHTML = "❌ İndirme Limitine Ulaşıldı";
                downloadBtn.style.backgroundColor = "var(--danger-color)";
                downloadBtn.style.cursor = "not-allowed";
                passwordSection.style.display = "none";
                lockBadge.style.display = "none";
            } else if (isExpired) {
                // Süre dolmuş
                downloadBtn.disabled = true;
                downloadBtn.innerHTML = "❌ Dosyanın Süresi Dolmuş";
                downloadBtn.style.backgroundColor = "var(--danger-color)";
                downloadBtn.style.cursor = "not-allowed";
                passwordSection.style.display = "none";
                lockBadge.style.display = "none";
            } else if (data.isLocked) {
                // Şifre korumalı (limit dolmamış ve süre dolmamış)
                passwordSection.style.display = "block"; 
                lockBadge.style.display = "block";       
                downloadBtn.innerHTML = "🔓 Kilidi Aç ve İndir"; 
                downloadBtn.style.backgroundColor = "var(--warning-color)";
                downloadBtn.disabled = false;
            } else {
                // Normal dosya
                passwordSection.style.display = "none";
                lockBadge.style.display = "none";
                downloadBtn.innerHTML = "<span>⬇️</span> Dosyayı İndir";
                downloadBtn.disabled = false;
            }
        })
        .catch(err => {
            // 410 durumunda (limit dolmuş veya süre dolmuş) özel mesaj göster
            if (err.message.includes("limit") || err.message.includes("süresi dolmuş")) {
                downloadBtn.disabled = true;
                downloadBtn.innerHTML = "❌ " + err.message;
                downloadBtn.style.backgroundColor = "var(--danger-color)";
                downloadBtn.style.cursor = "not-allowed";
                passwordSection.style.display = "none";
                lockBadge.style.display = "none";
            } else {
                alert(err.message);
                downloadBtn.disabled = true;
                downloadBtn.textContent = "İndirilemez";
            }
        });

    // --- 3. İNDİRME BUTONU ---
    downloadBtn.addEventListener("click", async () => {
        const password = passwordInput.value;
        
        // İndirme öncesi mevcut metadata'yı sakla
        if (!currentFileMetadata) {
            try {
                const metaRes = await fetch(`/api/files/${token}`);
                if (metaRes.ok) {
                    currentFileMetadata = await metaRes.json();
                }
            } catch (e) {
                // Metadata çekilemedi, devam et
            }
        }
        
        downloadBtn.innerHTML = "⏳ İndiriliyor...";
        downloadBtn.disabled = true;

        try {
            const res = await fetch(`/api/files/${token}/download`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });

            if (res.ok) {
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = fileNameDisplay.textContent; // Use displayed name
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();

                downloadBtn.innerHTML = "✅ İndirildi";
                downloadBtn.style.backgroundColor = "";
                
                // İndirme sonrası limit kontrolü yap
                setTimeout(async () => {
                    // Önce metadata'yı tekrar çekmeyi dene
                    let metaData = null;
                    try {
                        const metaRes = await fetch(`/api/files/${token}`);
                        if (metaRes.ok) {
                            metaData = await metaRes.json();
                            currentFileMetadata = metaData; // Güncel metadata'yı sakla
                        } else if (metaRes.status === 404) {
                            // Dosya silinmiş (burn-after-download veya limit dolmuş)
                            // Mevcut metadata'ya göre limit kontrolü yap
                            if (currentFileMetadata) {
                                const downloadCount = Number(currentFileMetadata.downloadCount) || 0;
                                const downloadLimit = Number(currentFileMetadata.downloadLimit) || 1;
                                // İndirme yapıldı, count artmış olmalı
                                if ((downloadCount + 1) >= downloadLimit || currentFileMetadata.isBurn) {
                                    downloadBtn.disabled = true;
                                    downloadBtn.innerHTML = "❌ İndirme Limitine Ulaşıldı";
                                    downloadBtn.style.backgroundColor = "var(--danger-color)";
                                    downloadBtn.style.cursor = "not-allowed";
                                    passwordSection.style.display = "none";
                                    lockBadge.style.display = "none";
                                    return;
                                }
                            }
                        }
                    } catch (metaErr) {
                        // Metadata çekilemedi, mevcut metadata'ya göre devam et
                    }
                    
                    // Metadata başarıyla çekildiyse limit kontrolü yap
                    if (metaData) {
                        const downloadCount = Number(metaData.downloadCount) || 0;
                        const downloadLimit = Number(metaData.downloadLimit) || 1;
                        const isLimitReached = metaData.isLimitReached === true || downloadCount >= downloadLimit;
                        const isExpired = metaData.isExpired === true || (Date.now() > Number(metaData.expiresAt));
                        
                        if (isLimitReached) {
                            // Limit dolmuş
                            downloadBtn.disabled = true;
                            downloadBtn.innerHTML = "❌ İndirme Limitine Ulaşıldı";
                            downloadBtn.style.backgroundColor = "var(--danger-color)";
                            downloadBtn.style.cursor = "not-allowed";
                            passwordSection.style.display = "none";
                            lockBadge.style.display = "none";
                        } else if (isExpired) {
                            // Süre dolmuş
                            downloadBtn.disabled = true;
                            downloadBtn.innerHTML = "❌ Dosyanın Süresi Dolmuş";
                            downloadBtn.style.backgroundColor = "var(--danger-color)";
                            downloadBtn.style.cursor = "not-allowed";
                            passwordSection.style.display = "none";
                            lockBadge.style.display = "none";
                        } else if (metaData.isLocked) {
                            // Şifre korumalı
                            passwordSection.style.display = "block";
                            lockBadge.style.display = "block";
                            downloadBtn.innerHTML = "🔓 Kilidi Aç ve İndir";
                            downloadBtn.style.backgroundColor = "var(--warning-color)";
                            downloadBtn.disabled = false;
                            if (passwordInput) passwordInput.value = ""; // Şifreyi temizle
                        } else {
                            // Normal dosya
                            passwordSection.style.display = "none";
                            lockBadge.style.display = "none";
                            downloadBtn.innerHTML = "<span class=\"btn-icon\">⬇️</span> Tekrar İndir";
                            downloadBtn.style.backgroundColor = "";
                            downloadBtn.disabled = false;
                        }
                    } else {
                        // Metadata çekilemedi, mevcut metadata'ya göre kontrol et
                        if (currentFileMetadata) {
                            const downloadCount = Number(currentFileMetadata.downloadCount) || 0;
                            const downloadLimit = Number(currentFileMetadata.downloadLimit) || 1;
                            if ((downloadCount + 1) >= downloadLimit || currentFileMetadata.isBurn) {
                                downloadBtn.disabled = true;
                                downloadBtn.innerHTML = "❌ İndirme Limitine Ulaşıldı";
                                downloadBtn.style.backgroundColor = "var(--danger-color)";
                                downloadBtn.style.cursor = "not-allowed";
                                passwordSection.style.display = "none";
                                lockBadge.style.display = "none";
                            } else {
                                downloadBtn.disabled = false;
                                downloadBtn.innerHTML = "<span class=\"btn-icon\">⬇️</span> Tekrar İndir";
                                downloadBtn.style.backgroundColor = "";
                            }
                        }
                    }
                }, 500);
            } else {
                const data = await res.json();
                throw new Error(data.error || "İndirme başarısız.");
            }
        } catch (err) {
            errorText.textContent = err.message;
            errorText.style.display = "block";
            if (passwordInput) {
                passwordInput.style.borderColor = "var(--danger-color)";
                passwordInput.style.animation = "shake 0.3s";
                setTimeout(() => passwordInput.style.animation = "", 300);
            }
            
            downloadBtn.disabled = false;
            downloadBtn.innerHTML = "🔓 Kilidi Aç ve İndir";
        }
    });

    if(passwordInput) {
        passwordInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") downloadBtn.click();
        });
    }

    // --- 4. RAPORLAMA MODALI MANTIĞI ---
    
    // Modalı Aç
    if (reportLink) {
        reportLink.addEventListener("click", (e) => {
            e.preventDefault(); // Sayfanın yukarı zıplamasını engelle
            reportModal.style.display = "flex";
        });
    }

    // Modalı Kapat (X butonu)
    if (closeReportBtn) {
        closeReportBtn.addEventListener("click", () => {
            reportModal.style.display = "none";
        });
    }

    // Rapor Gönder
    if (reportForm) {
        reportForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const title = document.getElementById("report-title").value;
            const description = document.getElementById("report-desc").value;

            try {
                const res = await fetch('/api/reports', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token, title, description })
                });
                
                if (res.ok) {
                    alert("Raporunuz iletildi. Teşekkürler.");
                    reportModal.style.display = "none";
                    reportForm.reset();
                } else {
                    alert("Rapor gönderilemedi.");
                }
            } catch (err) {
                alert("Sunucu hatası.");
            }
        });
    }

    // Modalı Kapat (Dışarı tıklama)
    if (reportModal) {
        window.addEventListener("click", (e) => {
            if (e.target === reportModal) {
                reportModal.style.display = "none";
            }
        });
    }
});

// CSS Animasyonu
const styleSheet = document.createElement("style");
styleSheet.innerText = `
@keyframes shake {
  0% { transform: translateX(0); }
  25% { transform: translateX(-5px); }
  50% { transform: translateX(5px); }
  75% { transform: translateX(-5px); }
  100% { transform: translateX(0); }
}
`;
document.head.appendChild(styleSheet);