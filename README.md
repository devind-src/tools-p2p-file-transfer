# P2PFileTransfer

Aplikasi **.NET 10** untuk mengirim file (terutama **file backup database**) antar server secara
**peer-to-peer**. Setiap server menginstal aplikasi yang sama; tidak ada server/klien khusus.
Setiap node bisa **menerima** file (HTTP listener) sekaligus **mengirim** file (job terjadwal)
ke node lain, jadi server A bisa kirim ke B dan B bisa kirim ke A.

```
        ┌──────────────────────────┐          HTTP/HTTPS            ┌──────────────────────────┐
        │  SERVER-A                │  ───── HMAC + AES-GCM ─────▶   │  SERVER-B                │
        │  P2PFileTransfer         │                                │  P2PFileTransfer         │
        │   • Scheduler (kirim)    │  ◀──── HMAC + AES-GCM ──────   │   • Scheduler (kirim)    │
        │   • Listener  (terima)   │                                │   • Listener  (terima)   │
        └──────────────────────────┘                                └──────────────────────────┘
```

## Fitur

| Kebutuhan | Implementasi |
|---|---|
| Peer-to-peer | Satu executable berisi listener (Kestrel) + scheduler pengirim. Semua node setara. |
| Konfigurasi di `appsettings.json` | Semua pengaturan ada di section `P2P` dan `Kestrel` (bisa juga di-override dengan environment variable, mis. `P2P__Security__ApiKey`). |
| Jalan rutin tiap hari | `Jobs[].Times` (mis. `["01:30", "13:30"]`), opsional `Days` (hari tertentu). Jadwal yang terlewat (server mati) tetap dijalankan jika terlambat ≤ `CatchUpMinutes`. |
| History / tidak kirim ulang | `data/sent-history.json` mencatat file (path + ukuran + waktu modifikasi + SHA-256) per job & per peer. Penerima juga menyimpan `data/received-log.json`, jadi walaupun history pengirim hilang file tidak dikirim ulang. |
| File backup DB | Chunked upload (default 4 MB), **resume** otomatis jika koneksi putus, verifikasi **SHA-256**, file yang masih ditulis (backup berjalan) dilewati dan dicoba lagi nanti. |
| HTTP/HTTPS + API key | Semua request ditandatangani HMAC-SHA256 dengan kunci turunan API key. Kredensial salah → ditolak (401) dan IP di-ban sementara. |
| Independen | Hanya memakai .NET 10 shared framework, **tanpa paket NuGet / library pihak ketiga**. Bisa di-publish *self-contained single file* sehingga server tujuan tidak perlu menginstal .NET. |

## Keamanan

1. **API key tidak pernah dikirim lewat jaringan.** Dari API key diturunkan dua kunci (HKDF-SHA256):
   satu untuk tanda tangan HMAC, satu untuk enkripsi. Setiap request membawa
   `X-P2P-Node`, `X-P2P-Timestamp`, `X-P2P-Nonce`, `X-P2P-Signature`
   (HMAC atas method, path, node, timestamp, nonce, dan hash body).
   Perbandingan tanda tangan memakai *constant-time compare*.
2. **Anti replay**: timestamp harus dalam jendela `ClockSkewSeconds` (default ±5 menit) dan nonce hanya
   bisa dipakai sekali.
3. **Respons juga ditandatangani** (terikat ke nonce request) → pengirim memverifikasi bahwa yang menjawab
   benar peer asli, bukan server palsu / man-in-the-middle. File baru dicatat "terkirim" jika respons valid.
4. **Isi file dienkripsi AES-256-GCM** per chunk (kunci unik per transfer, transfer-id + offset sebagai
   associated data) → tetap rahasia & tidak bisa dimodifikasi meskipun memakai HTTP biasa.
5. **Integritas end-to-end**: SHA-256 seluruh file diverifikasi penerima sebelum file dipindah ke folder tujuan;
   jika beda, file dibuang.
6. **Brute-force protection**: setelah `MaxFailedAttempts` kegagalan dalam `FailedAttemptWindowMinutes`, IP
   di-ban `BanMinutes` menit. Ditambah **rate limit** per IP (`RateLimitPerMinute`).
7. **IP allow-list** (`AllowedIPs`, mendukung CIDR). IP di luar daftar koneksinya langsung diputus.
8. **Allow-list nama node** (`AcceptOnlyKnownPeers`): hanya node yang terdaftar di `Peers` yang diterima.
9. **HTTPS** opsional/diwajibkan (`RequireHttps`), TLS 1.2/1.3 saja, dukungan **certificate pinning**
   (`CertificateThumbprint`, SHA-256) sehingga sertifikat self-signed tetap aman.
10. **Pengirim tidak bisa menentukan path**: pengirim hanya menyebut *alias* tujuan (`RemoteDestination`);
    path sebenarnya ditentukan penerima (`Receiver.Destinations`). Nama file divalidasi ketat
    (tanpa `..`, `/`, `\`, `:`, nama device Windows seperti `CON`), hanya **ekstensi yang diizinkan**, batas ukuran,
    dan pengecekan **sisa disk** sebelum menerima.
11. **Hardening HTTP**: header `Server` dihapus, batas ukuran body/header, timeout header, security headers
    (`nosniff`, `no-store`, CSP), path selain `/api/...` ditolak.
12. Validasi konfigurasi saat start: API key minimal 32 karakter dan placeholder ditolak.
13. Script instalasi Windows membatasi folder aplikasi (berisi API key) hanya untuk SYSTEM & Administrators,
    dan membuka firewall hanya untuk IP peer. Unit systemd memakai user khusus + sandboxing.

## Struktur Project

```
src/P2PFileTransfer/
  Program.cs                   entry point (mode service / CLI)
  AppSetup.cs                  konfigurasi host, Kestrel, rate limiter, DI
  appsettings.json             SEMUA konfigurasi
  Configuration/               model opsi + validasi
  Security/                    HMAC, AES-GCM, nonce cache, IP guard, middleware auth, sertifikat
  Receiving/                   endpoint penerima, penyimpanan chunk, housekeeping
  Sending/                     HTTP client ke peer, job runner, scheduler harian
  Storage/                     history (JSON, atomic write, file lock)
  Logging/                     file logger harian (tanpa library luar)
  Cli/                         perintah command line
deploy/
  install-windows.ps1          install sebagai task otomatis (start saat boot, auto restart)
  uninstall-windows.ps1
  p2p-transfer.service         unit systemd untuk Linux
publish.ps1 / publish.sh       build executable self-contained
```

## Build & Publish

Butuh .NET 10 SDK **hanya di mesin build**.

```bash
# Windows (PowerShell)
.\publish.ps1                       # hasil: publish\win-x64\ dan publish\linux-x64\

# Linux
./publish.sh                        # atau: ./publish.sh win-x64
```

Hasil publish tiap platform hanya 2 file: `P2PFileTransfer(.exe)` dan `appsettings.json`.

## Instalasi

Lakukan di **setiap** server.

1. Copy isi `publish/win-x64` (atau `linux-x64`) ke server, mis. `C:\P2PFileTransfer`.
2. Buat API key **sekali saja**, lalu pakai nilai yang sama di semua server:
   ```
   P2PFileTransfer.exe --generate-key
   ```
3. Edit `appsettings.json` (lihat contoh di bawah).
4. Tes konfigurasi & koneksi:
   ```
   P2PFileTransfer.exe --check
   ```
5. Pasang sebagai proses latar belakang:
   * **Windows** (PowerShell sebagai Administrator):
     ```powershell
     .\deploy\install-windows.ps1 -InstallDir C:\P2PFileTransfer -Port 5080 -RemoteAddress 192.168.1.20
     ```
     Task Scheduler akan menjalankan aplikasi saat boot sebagai SYSTEM dan me-restart otomatis jika berhenti.
   * **Linux**: lihat komentar di `deploy/p2p-transfer.service`.

> Pastikan jam kedua server sinkron (NTP / Windows Time), karena request dengan selisih waktu
> lebih dari `ClockSkewSeconds` ditolak.

## Contoh Konfigurasi 2 Server

**SERVER-A** (192.168.1.10) – mengirim backup ke B, sekaligus menerima backup dari B:

```jsonc
{
  "Kestrel": { "Endpoints": { "Http": { "Url": "http://0.0.0.0:5080" } } },
  "P2P": {
    "NodeName": "SERVER-A",
    "Security": {
      "ApiKey": "<hasil --generate-key, SAMA di semua server>",
      "AllowedIPs": [ "192.168.1.20" ]
    },
    "Receiver": {
      "Destinations": { "backups": "E:\\Replica\\Backups" },
      "AllowedExtensions": [ ".bak", ".trn" ]
    },
    "Peers": [ { "Name": "SERVER-B", "BaseUrl": "http://192.168.1.20:5080/" } ],
    "Jobs": [
      {
        "Name": "sql-backup",
        "SourceDirectory": "D:\\Backup\\SQL",
        "FilePatterns": [ "*.bak", "*.trn" ],
        "TargetPeers": [ "SERVER-B" ],
        "RemoteDestination": "backups",
        "Times": [ "01:30" ],
        "MaxFileAgeDays": 7
      }
    ]
  }
}
```

**SERVER-B** (192.168.1.20) – kebalikannya:

```jsonc
{
  "Kestrel": { "Endpoints": { "Http": { "Url": "http://0.0.0.0:5080" } } },
  "P2P": {
    "NodeName": "SERVER-B",
    "Security": { "ApiKey": "<API key yang sama>", "AllowedIPs": [ "192.168.1.10" ] },
    "Receiver": {
      "Destinations": { "backups": "E:\\Replica\\Backups" },
      "AllowedExtensions": [ ".bak", ".trn" ]
    },
    "Peers": [ { "Name": "SERVER-A", "BaseUrl": "http://192.168.1.10:5080/" } ],
    "Jobs": [
      {
        "Name": "sql-backup",
        "SourceDirectory": "D:\\Backup\\SQL",
        "FilePatterns": [ "*.bak" ],
        "TargetPeers": [ "SERVER-A" ],
        "RemoteDestination": "backups",
        "Times": [ "02:00" ]
      }
    ]
  }
}
```

File dari A akan tersimpan di B pada `E:\Replica\Backups\SERVER-A\<nama file>`
(`SeparateFolderPerSender: true`).

Satu job boleh mengirim ke beberapa peer sekaligus (`"TargetPeers": ["SERVER-B", "SERVER-C"]`).
Node yang hanya menerima cukup tidak punya `Jobs`; node yang hanya mengirim bisa `Receiver.Enabled: false`.

## Mengaktifkan HTTPS (disarankan)

```powershell
# di SERVER-B: buat sertifikat self-signed (password ditanyakan)
P2PFileTransfer.exe --generate-cert C:\P2PFileTransfer\server-b.pfx --cn server-b --ip 192.168.1.20
```

Output menampilkan **SHA-256 thumbprint**. Lalu:

* `appsettings.json` SERVER-B:
  ```json
  "Kestrel": { "Endpoints": { "Https": { "Url": "https://0.0.0.0:5443",
      "Certificate": { "Path": "C:\\P2PFileTransfer\\server-b.pfx", "Password": "<password>" } } } },
  "P2P": { "Security": { "RequireHttps": true, ... } }
  ```
  (Password bisa juga diberikan lewat environment variable `Kestrel__Endpoints__Https__Certificate__Password`.)
* `appsettings.json` SERVER-A, pada peer SERVER-B:
  ```json
  { "Name": "SERVER-B", "BaseUrl": "https://192.168.1.20:5443/", "CertificateThumbprint": "<thumbprint>" }
  ```

Jika memakai sertifikat dari CA yang dipercaya, `CertificateThumbprint` boleh dikosongkan.
Thumbprint sertifikat yang sudah ada: `P2PFileTransfer.exe --thumbprint file.pfx`.

## Referensi Konfigurasi (`P2P`)

| Kunci | Default | Keterangan |
|---|---|---|
| `NodeName` | – | Nama unik node ini (huruf, angka, `.` `_` `-`). |
| `DataDirectory` | `data` | Lokasi history, state scheduler, file lock. Path relatif = relatif ke folder exe. |
| **Security** | | |
| `ApiKey` | – | Rahasia bersama, min. 32 karakter. Harus sama di semua node. |
| `ClockSkewSeconds` | `300` | Toleransi selisih jam antar server. |
| `RequireHttps` | `false` | Tolak request yang bukan HTTPS. |
| `AcceptOnlyKnownPeers` | `true` | Hanya terima node yang ada di `Peers`. |
| `AllowedIPs` | `[]` | IP/CIDR yang boleh konek (kosong = semua). Contoh `["10.0.0.5", "10.1.0.0/24"]`. |
| `MaxFailedAttempts` / `FailedAttemptWindowMinutes` / `BanMinutes` | `5` / `10` / `30` | Ban IP setelah gagal autentikasi berulang. |
| `RateLimitPerMinute` | `3000` | Maks request per menit per IP (0 = tanpa batas). |
| **Receiver** | | |
| `Enabled` | `true` | Aktifkan penerimaan file. |
| `Destinations` | – | `alias → folder`. Pengirim hanya bisa memilih alias. |
| `SeparateFolderPerSender` | `true` | Simpan di sub-folder bernama node pengirim. |
| `AllowedExtensions` | – | Ekstensi yang diterima (kosong = semua, tidak disarankan). |
| `MaxFileSizeMB` | `0` | Batas ukuran file (0 = tanpa batas). |
| `MaxChunkSizeMB` | `16` | Ukuran chunk maksimum yang diterima (≥ `Sender.ChunkSizeMB` di peer). |
| `MinFreeDiskSpaceMB` | `1024` | Sisa disk minimum setelah file diterima. |
| `OverwriteExisting` | `false` | `false` = file lama dipertahankan, file baru diberi suffix waktu. |
| `IncompleteTransferExpiryHours` | `48` | Transfer setengah jalan dihapus setelah sekian jam tidak aktif. |
| **Sender** | | |
| `ChunkSizeMB` | `4` | Ukuran potongan per request. |
| `MaxRetries` / `RetryDelaySeconds` | `5` / `30` | Percobaan ulang (lanjut dari offset terakhir). |
| `RequestTimeoutSeconds` | `600` | Timeout per request. |
| `MinFileAgeMinutes` | `5` | File yang baru diubah dianggap masih ditulis → dilewati. |
| `CatchUpMinutes` | `120` | Jadwal yang terlewat tetap dijalankan jika terlambat ≤ nilai ini. |
| **Peers[]** | | |
| `Name` | – | Harus sama dengan `NodeName` di server tersebut. |
| `BaseUrl` | – | `http://host:port/` atau `https://host:port/`. |
| `CertificateThumbprint` | – | SHA-256 thumbprint untuk pinning sertifikat. |
| `AllowInvalidCertificate` | `false` | Terima sertifikat apa saja (tidak disarankan). |
| **Jobs[]** | | |
| `Name`, `Enabled` | | Nama job & aktif/tidak. |
| `SourceDirectory` | – | Folder sumber backup. |
| `FilePatterns` | `["*"]` | Pola file, mis. `["*.bak", "*.trn"]`. |
| `IncludeSubdirectories` | `false` | Ikut sub-folder. |
| `TargetPeers` | – | Daftar nama peer tujuan. |
| `RemoteDestination` | – | Alias tujuan di `Receiver.Destinations` milik peer. |
| `Times` | – | Jam lokal `HH:mm`. Kosong = hanya manual (`--run-job`). |
| `Days` | `[]` | Mis. `["Monday", "Thursday"]`. Kosong = setiap hari. |
| `MaxFileAgeDays` | `0` | Hanya kirim file yang diubah dalam N hari terakhir (berguna saat pertama kali dipasang agar backup lama tidak ikut terkirim). |
| **FileLog** | | |
| `Enabled`, `Directory`, `RetentionDays` | `true`, `logs`, `30` | Log harian `logs/p2p-yyyyMMdd.log`. |

## Command Line

```
P2PFileTransfer                          jalankan sebagai service (terima file + jadwal kirim)
P2PFileTransfer --run-job <nama|all>     jalankan job sekarang juga lalu keluar
P2PFileTransfer --check                  validasi konfigurasi + tes koneksi & jam ke semua peer
P2PFileTransfer --history [job]          tampilkan history file terkirim
P2PFileTransfer --generate-key           buat API key acak (384 bit)
P2PFileTransfer --generate-cert <out.pfx> [--cn nama] [--dns a,b] [--ip x,y] [--years 5]
P2PFileTransfer --thumbprint <file.pfx|file.cer>
```

Exit code: `0` sukses, `1` konfigurasi salah, `2` argumen salah, `3` ada file/peer yang gagal
(berguna jika `--run-job` dipanggil dari script lain, mis. langsung setelah job backup SQL Agent).

`--run-job` aman dijalankan bersamaan dengan service: job yang sama tidak akan berjalan dua kali
(file lock), dan history ditulis dengan lock antar-proses.

## File Data

| File | Isi |
|---|---|
| `data/sent-history.json` | File yang sudah terkirim (job, peer, path, ukuran, waktu, SHA-256, nama di tujuan). Entri untuk file yang sudah dihapus dari sumber dibersihkan otomatis setelah 7 hari. |
| `data/received-log.json` | File yang diterima node ini dari peer. |
| `data/scheduler-state.json` | Waktu terakhir tiap job dijalankan (mencegah dobel run setelah restart). |
| `<destination>/.incoming/` | Transfer yang sedang berjalan / bisa di-resume. |
| `logs/p2p-yyyyMMdd.log` | Log aplikasi. |

Untuk memaksa sebuah file dikirim ulang, hapus entrinya dari `sent-history.json`
(dan dari `received-log.json` di penerima jika file tujuan juga sudah dihapus).

## Protokol (ringkas)

| Method & Path | Fungsi |
|---|---|
| `GET /api/v1/ping` | Cek koneksi, versi dan jam peer. |
| `POST /api/v1/transfers` | Mulai/resume transfer `{fileName, size, sha256, destination}` → `{transferId, status, offset}`. `status` = `Ready` atau `AlreadyExists`. |
| `PUT /api/v1/transfers/{id}/chunks/{offset}` | Kirim chunk terenkripsi (`nonce ‖ ciphertext ‖ tag`). |
| `POST /api/v1/transfers/{id}/complete` | Verifikasi SHA-256, pindahkan file ke folder tujuan. |

Tanda tangan request:
`Base64(HMAC-SHA256(K_auth, "P2P-HMAC-SHA256-REQUEST\n" + METHOD + "\n" + path + "\n" + node + "\n" + timestamp + "\n" + nonce + "\n" + hex(SHA256(body))))`,
dengan `K_auth = HKDF-SHA256(ApiKey, salt="tools-p2p/file-transfer/v1", info="hmac-authentication")`.

## Troubleshooting

| Gejala | Penyebab / solusi |
|---|---|
| `401 ... outside the allowed window` | Jam server berbeda > `ClockSkewSeconds`. Sinkronkan NTP. |
| `401 unauthorized` | API key berbeda antar server. |
| `403 forbidden` terus-menerus | IP di-ban karena terlalu banyak gagal login; tunggu `BanMinutes` atau restart aplikasi penerima. |
| `403 node not allowed` | `NodeName` pengirim belum ada di `Peers` penerima. |
| `400 unknown destination` | `RemoteDestination` job tidak ada di `Receiver.Destinations` penerima. |
| `400 file extension ... not allowed` | Tambahkan ekstensi di `AllowedExtensions` penerima. |
| `507 insufficient disk space` | Disk penerima penuh / di bawah `MinFreeDiskSpaceMB`. |
| `TLS certificate ... does not match the pinned thumbprint` | Sertifikat peer berganti; perbarui `CertificateThumbprint`. |
| File tidak terkirim, log "modified less than N minutes ago" | Backup masih ditulis; akan dikirim di jadwal berikutnya. |
