# Eduka-Block 0.4.2

Eduka-Block adalah aplikasi perlindungan web cerdas untuk **Edukasaun OS**. Aplikasi ini membantu orang tua dan guru memblokir situs pornografi, malware, penipuan, perjudian, media sosial, alamat IP, rentang jaringan, dan website lain yang dinilai merusak anak atau siswa.

Versi 0.4.2 memperbaiki kegagalan firewall ketika IP/rentang saling tumpang tindih, dependency PolicyKit untuk Debian 13, dan lock helper yang dapat disalahgunakan pengguna biasa. Versi ini juga menambahkan **impor/ekspor aturan**, penghapusan banyak aturan sekaligus, tombol **Sinkronkan IP sekarang**, kolom yang dapat diurutkan, antarmuka yang tidak lagi membeku saat bekerja, dan terjemahan lengkap untuk semua pesan. Rincian ada di `CHANGELOG.md`.

Patch 0.4.1 memperbarui antarmuka menjadi **soft 3D** yang ringan: kedalaman dibuat dengan bayangan kecil dan border bertingkat tanpa membuat kartu atau tombol terlihat menonjol berlebihan. Daftar aturan kini memberi setiap website/IP aktif tanda merah **● DIBLOKIR**. Mesin DNS, hosts, nftables, Smart IP, dan Squid dari 0.4 tetap dipertahankan serta diperkeras.

## Bahasa

Bahasa default adalah **English (International)**. Pilihan bahasa tersedia langsung pada dialog login dan halaman utama:

- English (International)
- Tetum
- Português (Portugal)
- Português (Brasil)
- Bahasa Indonesia

Pilihan disimpan per pengguna Linux di `~/.config/eduka-block/settings.json` dan dapat diganti tanpa menginstal ulang aplikasi.

## Desain soft 3D

- Tidak memakai gradient atau bayangan berat; kedalaman menggunakan shadow 1–4 px yang lembut.
- Kartu, bidang formulir, judul, keterangan, hint, status, dan catatan memiliki kotak yang rapi.
- Radius sudut, garis batas, padding, dan tinggi kontrol dibuat konsisten.
- Warna diambil dari tema GTK aktif; tidak ada palet paksa yang menyulitkan pembacaan.
- Website dan IP yang aktif pada daftar diberi status merah **● DIBLOKIR** agar mudah dikenali.
- Ukuran default menjadi 900×600 dan ukuran minimum 700×500 untuk layar kecil.
- Header, logo, dialog login, jarak antarkartu, padding, dan tinggi kontrol diperkecil.
- Mesin keamanan dan seluruh pilihan bahasa versi sebelumnya tetap dipertahankan.

## Fitur utama

- Login khusus orang tua/guru setiap kali aplikasi dibuka.
- Pembuatan/perubahan akun meminta password minimal 5 karakter dan konfirmasi password kedua yang harus sama.
- Menu ganti username/password tersedia pada layar login dan tetap memerlukan akun lama yang benar serta otorisasi administrator OS.
- Password disimpan sebagai hash PBKDF2-SHA256 bersalt, bukan password asli.
- File akun teks tetap berada di `/usr/share/Eduka-Block/credentials.txt`.
- Tema GTK adaptif tanpa memaksa palet gelap versi 0.1.
- Blokir URL, domain, IPv4, IPv6, IPv4 CIDR, dan IPv6 CIDR.
- Ekstraksi domain otomatis dari URL HTTP/HTTPS.
- Perlindungan wildcard untuk seluruh subdomain melalui DNS lokal NetworkManager/dnsmasq.
- Fallback domain melalui bagian khusus Eduka-Block pada `/etc/hosts`.
- Firewall nftables untuk IP, CIDR, dan alamat IP yang dipelajari secara cerdas.
- **Smart IP Tracking**: mencari ulang record A/AAAA domain setiap 15 menit dan memperbarui firewall ketika IP berubah.
- Timer systemd tetap bekerja setelah restart dan mengejar pembaruan yang terlewat ketika komputer dimatikan.
- Perlindungan konten dewasa opsional menggunakan daftar `porn-only` StevenBlack/hosts.
- Tab Squid Proxy terpisah dengan switch, status service, petunjuk koneksi, serta tambah/hapus kata yang diblokir.
- Konfigurasi Squid diuji sebelum reload dan dipulihkan otomatis jika tidak valid.
- Port Squid yang dikelola hanya terikat ke `127.0.0.1:3128`; listener default dipulihkan ketika fitur dinonaktifkan.
- Kategori manual, pencarian, status cakupan, jumlah IP terlacak, auto-lock 10 menit, dan PolicyKit.
- Migrasi otomatis database versi lama ke schema versi 3 tanpa menghapus daftar atau pengaturan lama.
- **Impor aturan** dari daftar teks biasa, file ekspor Eduka-Block, atau blocklist format hosts (`0.0.0.0 domain`) — maksimal 1.000 entri dengan satu otorisasi.
- **Ekspor aturan** ke file teks (`domain  # Kategori`) untuk dipindahkan ke komputer lain.
- Pilih dan hapus beberapa aturan sekaligus (Ctrl/Shift + klik, lalu **Hapus yang Dipilih** atau tombol Delete).
- Tombol **Sinkronkan alamat IP sekarang** dan waktu sinkronisasi terakhir di kartu ringkasan.
- Subdomain yang sudah tercakup domain induk yang diblokir (misalnya `video.example.org` saat `example.org` sudah diblokir) langsung diberi tahu, tidak ditambahkan dua kali.
- Pintasan keyboard: **Ctrl+F** mencari aturan, **Ctrl+L** mengunci aplikasi.

## Perlindungan lintas browser

Eduka-Block bekerja pada lapisan sistem operasi, bukan sebagai ekstensi browser:

1. **Wildcard DNS** menolak domain utama dan seluruh subdomain melalui plugin dnsmasq milik NetworkManager.
2. **`/etc/hosts` fallback** menolak domain utama dan pasangan umum `www`.
3. **nftables** memblokir IP/rentang yang dimasukkan dan IP publik yang dipelajari dari domain.
4. **Smart IP Sync** memperbarui A/AAAA setiap 15 menit menggunakan DNS upstream NetworkManager sebelum memasukkannya ke firewall.

Karena perlindungan berada di bawah lapisan browser, browser normal yang menggunakan jaringan komputer menerima aturan yang sama. Ini mencakup Firefox, Chromium/Chrome, Brave, Vivaldi, Falkon, Epiphany, Midori, Konqueror, browser CLI, dan aplikasi lain yang menggunakan resolver/jaringan sistem.

Tidak ada aplikasi kontrol lokal yang dapat menjamin 100% terhadap pengguna dengan akses root, boot USB/OS lain, virtual machine, browser jarak jauh, VPN, Tor, atau proxy eksternal. Akun anak/siswa harus berupa akun Linux non-administrator.

## Squid Proxy dan pemblokiran kata

APT memasang dependency `squid` secara otomatis. Saat switch Squid diaktifkan, Eduka-Block:

1. Memvalidasi 1–100 kata literal; regex mentah tidak diterima.
2. Menghasilkan ACL `url_regex` dan `dstdom_regex` sebelum rule `http_access allow`, menolak client non-lokal, dan mengikat listener ke localhost.
3. Menjalankan `squid -k parse`; kegagalan mengembalikan konfigurasi sebelumnya.
4. Mengaktifkan dan menjalankan service Squid pada proxy lokal `127.0.0.1:3128`.

Daftar awal mencakup `adult`, `hentai`, `nude`, `porn`, `porno`, `pornography`, `seks`, `sex`, `xnxx`, `xvideos`, dan `xxx`. Kata yang terlalu umum dapat menyebabkan false positive dan harus ditinjau orang tua/guru.

Browser yang memakai tab Squid harus dikonfigurasi menggunakan proxy HTTP dan HTTPS `127.0.0.1`, port `3128`. Untuk HTTP, Squid dapat melihat URL lengkap. Untuk HTTPS forward proxy, Squid dapat menolak hostname tujuan tetapi tidak membaca path atau isi terenkripsi tanpa SSL interception. Eduka-Block sengaja tidak memasang CA atau melakukan SSL bump karena tindakan tersebut melemahkan privasi dan menambah risiko keamanan. DNS, hosts, dan firewall tetap menjadi lapisan sistem utama.

## Tentang subdomain dan IP baru

- Rule domain `example.org` juga menghasilkan wildcard DNS untuk subdomain seperti `video.example.org`, `cdn.example.org`, atau subdomain baru.
- Smart IP Tracking menyimpan IP A/AAAA publik saat ini dan memperbaruinya secara berkala.
- Jika browser mencoba IP yang sudah dipelajari secara langsung, nftables tetap memblokir koneksi.
- IP/CDN dapat digunakan bersama oleh banyak website. Karena itu Eduka-Block **tidak menebak dan memblokir seluruh subnet secara otomatis**; tindakan tersebut dapat merusak website yang tidak terkait.
- Orang tua/guru dapat memasukkan CIDR secara eksplisit, misalnya `203.0.113.0/24`, setelah memahami dampaknya.
- Smart IP Tracking dapat dinonaktifkan saat menambahkan domain yang memakai hosting/CDN bersama.

## Instalasi dan upgrade

Gunakan APT agar seluruh dependency diunduh otomatis:

```bash
sudo apt install ./eduka-block_0.4.2-1_all.deb
```

Jika versi lama (0.1–0.4.1) sudah terpasang, perintah yang sama meng-upgrade aplikasi dan mempertahankan akun serta daftar blokir.

Dependency utama:

- `python3`, `python3-gi`, `python3-dnspython`
- `gir1.2-gtk-3.0`
- `pkexec` dan `polkitd` (atau `policykit-1` pada rilis Debian lama)
- `nftables`
- `network-manager`, `dnsmasq-base`
- `squid`
- `ca-certificates`
- `lxqt-policykit` direkomendasikan untuk Eduka-Desktop/LXQt

Launcher berada di kategori **System / Settings → Eduka-Block**.

## Komponen sistem

| Lokasi | Fungsi |
| --- | --- |
| `/usr/share/Eduka-Block/credentials.txt` | Username, algoritma, salt, dan hash password |
| `/var/lib/eduka-block/blocklist.json` | Database rule schema 3, IP, dan pengaturan Squid |
| `/var/lib/eduka-block/adult-domains.txt` | Cache daftar konten dewasa |
| `/var/lib/eduka-block/hosts.original-backup` | Backup awal `/etc/hosts` |
| `/etc/hosts` | Fallback domain terkelola |
| `/etc/NetworkManager/conf.d/90-eduka-block-dns.conf` | Mengaktifkan plugin DNS dnsmasq NetworkManager |
| `/etc/NetworkManager/dnsmasq.d/eduka-block.conf` | Wildcard domain/subdomain yang dibuat aplikasi |
| `/etc/squid/eduka-block.conf` | ACL Squid yang dikelola Eduka-Block |
| `/etc/squid/eduka-block-keywords.txt` | Pola aman yang dibuat dari kata blokir |
| `/var/lib/eduka-block/squid.conf.original-backup` | Backup konfigurasi Squid sebelum integrasi pertama |
| nftables table `inet eduka_block` | IP, CIDR, dan IP hasil Smart Tracking |
| `eduka-block-firewall.service` | Memulihkan perlindungan setelah boot |
| `eduka-block-sync.timer` | Memperbarui IP setiap 15 menit |

NetworkManager mendukung plugin `dnsmasq` dan konfigurasi tambahan di `/etc/NetworkManager/dnsmasq.d/`. Eduka-Block menggunakan `nmcli general reload dns-full` agar perubahan rule DNS berlaku tanpa restart seluruh komputer.

## Keamanan dan batasan

- Setiap perubahan sistem membutuhkan PolicyKit dan otorisasi administrator OS.
- Helper root hanya menerima JSON terbatas, memvalidasi ulang input, dan tidak menjalankan shell.
- `/etc/hosts`, database, dan konfigurasi DNS ditulis secara atomik.
- Perubahan nftables diperiksa lebih dahulu dan mengganti tabel `inet eduka_block` dalam satu transaksi atomik, sehingga tidak ada jeda perlindungan ketika rule diperbarui.
- Lock proses di `/run/eduka-block.lock` (direktori milik root, bukan `/run/lock` yang dapat ditulis semua pengguna) mencegah timer Smart IP, service boot, dan perubahan UI menulis state secara bersamaan. Menunggu lock dibatasi 90 detik; DNS lookup dan unduhan daftar dilakukan sebelum lock diambil.
- IP dan rentang yang saling tumpang tindih digabung sebelum dimasukkan ke nftables sehingga penerapan firewall tidak gagal.
- Kata Squid dibatasi pada data literal 2–40 karakter dan diubah menjadi pola aman oleh helper; pengguna tidak dapat menyuntikkan directive atau regex mentah.
- Include Squid disisipkan sebelum allow rule, konfigurasi diperiksa dengan `squid -k parse`, dan perubahan memiliki rollback.
- Transaksi rollback mengembalikan state sebelumnya jika penerapan gagal.
- CIDR terlalu luas (`< /8` IPv4 atau `< /32` IPv6) ditolak untuk mengurangi kesalahan besar.
- Smart IP hanya menerima alamat publik hasil A/AAAA; jawaban lokal, loopback, multicast, atau invalid diabaikan.
- Resolver memakai DNS upstream dari `/run/NetworkManager/no-stub-resolv.conf`; fallback publik hanya digunakan jika tidak ada upstream yang valid.
- Daftar pihak ketiga mungkin memiliki false positive atau domain yang belum tercakup.
- Eduka-Block adalah alat bantu; tetap diperlukan pendidikan digital dan pengawasan orang tua/guru.

## Build dan test

```bash
./build.sh
python3 -m unittest discover -s tests -v
```

Versi aplikasi hanya didefinisikan di `src/eduka_block_common.py` (`APP_VERSION`); `build.sh` membacanya dan menghitung `Installed-Size` secara otomatis. Revisi paket dapat diganti dengan `PACKAGE_REVISION=2 ./build.sh`.

Untuk mencoba antarmuka langsung dari source checkout (helper tetap harus terpasang di `/usr/lib/eduka-block`):

```bash
python3 src/eduka_block.py
```

Hasil build:

```text
dist/eduka-block_0.4.2-1_all.deb
```

## Menghapus aplikasi

```bash
sudo apt remove eduka-block
```

Perintah tersebut melepaskan rule hosts, dnsmasq, firewall, timer, dan ACL Squid milik Eduka-Block, tetapi mempertahankan data agar dapat digunakan saat instalasi ulang. Untuk menghapus semuanya:

```bash
sudo apt purge eduka-block
```

## Proyek

- Nama: **Eduka-Block**
- Versi aplikasi: **0.4.2**
- Versi paket: **0.4.2-1**
- Target: Edukasaun OS berbasis Debian 13 dan Eduka-Desktop/LXQt
- Developer: **STI-MCAS & IDEA**
- Project lead: **Hugo Moniz do Rego**
- Website: <https://edukasaunos.tl>
- Lisensi: GPL-3.0-or-later

Eduka-Block masih terus dikembangkan. Fitur masa depan dapat mencakup whitelist, jadwal, profil per pengguna, laporan percobaan akses, mode sekolah terpusat, preset kategori (media sosial/perjudian), dan pembaruan blocklist terjadwal.
