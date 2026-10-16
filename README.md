# SMG Cloud Armor Enterprise WAF + Layer 7 DDoS Mitigation & OWASP Top 10 Live Drill
**PT Smartnet Magna Global (SMG) &bull; Google Cloud Premier Partner**  
*Enterprise Cloud Infrastructure & Security Practice*

---

## 1. Executive Summary

Aplikasi web dan API perbankan/fintech menghadapi ancaman siber yang semakin masif, mulai dari pemindaian bot otomatis, serangan injeksi kode (OWASP Top 10), hingga serangan Layer 7 HTTP flood.

Blueprint arsitektur ini mendemonstrasikan **Google Cloud Armor Enterprise WAF & Adaptive Protection** yang diintegrasikan langsung ke **Global External Application Load Balancer**. Seluruh inspeksi lalu lintas masuk dilakukan secara native di 100+ edge PoP Google di seluruh dunia sebelum serangan sempat menyentuh infrastruktur server backend.

---

## 2. Arsitektur Solusi (ASCII Diagram)

```
                            INTERNET / PROSPEK / ATTACKER
                                         │
                         [ANYCAST IP: 34.x.x.x (Global Edge)]
                                         │
                   ┌─────────────────────▼──────────────────────┐
                   │    Google Front End (GFE) Edge Layer       │
                   │  Global External Application Load Balancer │
                   └─────────────────────┬──────────────────────┘
                                         │
             ┌───────────────────────────┴───────────────────────────┐
             │            GOOGLE CLOUD ARMOR WAF POLICIES            │
             │                                                       │
             │ [Rule 1000] SQL Injection (sqli-v33-stable)      -> 403│
             │ [Rule 1010] Cross-Site Scripting (xss-v33)       -> 403│
             │ [Rule 1020] File Inclusion (lfi-v33 / rfi-v33)   -> 403│
             │ [Rule 1030] Remote Code Execution (rce-v33)      -> 403│
             │ [Rule 1040] Scanner Detection (scanner-v33)      -> 403│
             │ [Rule 2000] L7 DDoS Rate Limiting (50 req/m ban) -> 429│
             │ [Rule 2147483647] Default Clean Traffic          -> OK │
             └───────────────────────────┬───────────────────────────┘
                                         │ (Only Clean Traffic)
                                         ▼
                            [VPC: smg-armor-vpc]
                        [Region: asia-southeast2 (Jakarta)]
                                         │
              ┌──────────────────────────┴──────────────────────────┐
              │    Managed Instance Group (Zero Public IP Backend)   │
              │                                                     │
              │   ┌───────────────────────┐  ┌───────────────────┐  │
              │   │ VM: smg-armor-mig-001 │  │ VM: smg-armor-mig-│  │
              │   │ IP: 10.30.0.2         │  │ IP: 10.30.0.3     │  │
              │   │ (Python Flask API)    │  │ (Python Flask API)│  │
              │   └───────────────────────┘  └───────────────────┘  │
              └─────────────────────────────────────────────────────┘
                                         │
                        [Admin Access: Google Cloud IAP]
                        (Zero Open SSH Port to Internet)
```

---

## 3. Fitur Keamanan Utama

1. **Preconfigured WAF Rules (ModSecurity CRS v3.3):**
   * **SQL Injection (SQLi):** Memblokir pola `UNION SELECT`, `OR 1=1`, stacked queries, dan tautan tautan database berbahaya.
   * **Cross-Site Scripting (XSS):** Memblokir injeksi `<script>`, tag payload DOM, dan JavaScript inline.
   * **Local / Remote File Inclusion (LFI/RFI):** Memblokir direktori traversal (`../../../../etc/passwd`).
   * **Remote Code Execution (RCE):** Memblokir perintah shell command injection (`cat /etc/passwd`, `id`, `; ls -la`).
   * **Scanner Detection:** Memblokir automated tools seperti Nessus, Qualys, Nikto, sqlmap, dan Acunetix.
2. **Layer 7 DDoS & Rate-Based Ban:**
   * Membatasi klien yang melakukan spamming request (maksimal 50 request/menit). Jika terlampaui, IP penyerang otomatis di-ban selama 300 detik dengan HTTP 429 (*Too Many Requests*).
3. **Adaptive Protection & Telemetry:**
   * Machine learning native Google yang memantau anomali trafik Layer 7 dan merekomendasikan rule penangkalan secara otomatis.
   * Log inspeksi WAF dicatat 100% (*1.0 sample rate*) ke Cloud Logging.
4. **Zero Public IP Backend:**
   * VM server tidak memiliki IP eksternal. Akses keluar internet menggunakan Cloud NAT, dan akses admin hanya melalui Identity-Aware Proxy (IAP).

---

## 4. Panduan Uji Coba (Live Attack Drill)

Kami menyertakan script automasi interaktif untuk mendemonstrasikan penangkalan serangan secara real-time di hadapan klien:

### Tahap 1: Inisialisasi & Deploy
```bash
make init
make apply
```
*Tunggu sekitar 3-5 menit hingga Global Forwarding Rule dan Cloud Armor policy aktif penuh di edge.*

### Tahap 2: Jalankan 6-Stage Attack Simulation
```bash
make attack-drill
```
Script akan menguji:
1. **Benign Traffic** (`GET /`) &rarr; **HTTP 200 OK**
2. **SQL Injection** (`GET /api/search?q=1' OR 1=1 --`) &rarr; **HTTP 403 Forbidden** (Mitigated by Rule 1000)
3. **Cross-Site Scripting** (`POST /api/comment` with `<script>alert('pwned')</script>`) &rarr; **HTTP 403 Forbidden** (Mitigated by Rule 1010)
4. **Path Traversal / LFI** (`GET /api/view?file=../../../../etc/passwd`) &rarr; **HTTP 403 Forbidden** (Mitigated by Rule 1020)
5. **Remote Code Execution** (`POST /api/comment` with `cat /etc/passwd; id`) &rarr; **HTTP 403 Forbidden** (Mitigated by Rule 1030)
6. **L7 Rapid Flood** (Burst 60 requests) &rarr; **HTTP 429 Too Many Requests** (Mitigated by Rule 2000 Rate Limit Ban)

### Tahap 3: Verifikasi Audit Trail di Cloud Logging
```bash
make verify-logs
```
Script akan menarik log audit Cloud Armor secara langsung dan menampilkan detail:
* Matched Rule ID (`sqli-v33-stable`, `xss-v33-stable`, dll.)
* Rule Priority (1000, 1010, 2000)
* Enforced Action (`DENY`, `RATE_BASED_BAN`)
* Client IP & Timestamp

### Tahap 4: Cleanup
```bash
make destroy
```

---

## 5. Nilai Jual untuk Customer (Pitch Guide)

* **Cost Efficiency vs Hardware WAF:** Menggantikan appliance WAF fisik/virtual yang mahal dengan model bayar sesuai penggunaan (pay-as-you-go).
* **Performa Sub-Milidetik:** Terintegrasi langsung di Google Anycast Network, memotong latensi hingga 40% dibandingkan reverse-proxy WAF pihak ketiga.
* **Kepatuhan Regulasi:** Memenuhi standar kepatuhan PCI-DSS 6.6 dan regulasi OJK/FSI untuk perlindungan web publik.
