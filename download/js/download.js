document.addEventListener("DOMContentLoaded", () => {
    
    // --- ELEMENTLER ---
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

    // --- 1. DURUM SİMÜLASYONU ---
    const urlParams = new URLSearchParams(window.location.search);
    const isLocked = urlParams.get('locked') === 'true';
    const fileName = urlParams.get('name') || "proje_dosyasi_final.zip";

    if(fileNameDisplay) fileNameDisplay.textContent = fileName;

    if (isLocked) {
        passwordSection.style.display = "block"; 
        lockBadge.style.display = "block";       
        downloadBtn.innerHTML = "🔓 Kilidi Aç ve İndir"; 
        downloadBtn.style.backgroundColor = "var(--warning-color)";
    } else {
        passwordSection.style.display = "none";
        lockBadge.style.display = "none";
        downloadBtn.innerHTML = "<span>⬇️</span> Dosyayı İndir";
    }

    // --- 2. İNDİRME BUTONU ---
    downloadBtn.addEventListener("click", () => {
        if (isLocked) {
            const userPass = passwordInput.value;
            if (userPass === "1234") { 
                errorText.style.display = "none";
                passwordInput.style.borderColor = "var(--accent-color)";
                downloadBtn.innerHTML = "⏳ İndiriliyor...";
                downloadBtn.style.backgroundColor = "var(--accent-color)"; 
                setTimeout(() => alert("Dosya başarıyla indi!"), 500);
            } else {
                errorText.style.display = "block";
                passwordInput.style.borderColor = "var(--danger-color)";
                passwordInput.style.animation = "shake 0.3s";
                setTimeout(() => passwordInput.style.animation = "", 300);
            }
        } else {
            alert("Dosya indiriliyor...");
        }
    });

    if(passwordInput) {
        passwordInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") downloadBtn.click();
        });
    }

    // --- 3. RAPORLAMA MODALI MANTIĞI ---
    
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

    // Modalı Kapat (Dışarı tıklama)
    window.addEventListener("click", (e) => {
        if (e.target === reportModal) {
            reportModal.style.display = "none";
        }
    });

    // Rapor Formu Gönderimi
    if (reportForm) {
        reportForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const title = document.getElementById("report-title").value;
            
            // Simülasyon
            alert(`Raporunuz iletildi.\nBaşlık: ${title}\nTeşekkürler.`);
            
            // Formu temizle ve kapat
            reportForm.reset();
            reportModal.style.display = "none";
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