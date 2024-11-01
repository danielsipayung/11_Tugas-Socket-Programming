
# Aplikasi Chat Room dengan Enkripsi RSA dan TCP Over UDP

Proyek ini adalah aplikasi chat room berbasis Python yang menggunakan protokol UDP dengan tambahan simulasi TCP over UDP untuk meningkatkan reliabilitas transmisi data. Aplikasi ini juga memanfaatkan enkripsi RSA untuk menjaga keamanan pesan antar pengguna.

## Fitur

- **Protokol UDP dengan TCP Over UDP**: Menyediakan simulasi koneksi TCP di atas UDP dengan tiga-way handshake (SYN, SYN-ACK, ACK).
- **Enkripsi RSA**: Pesan dienkripsi menggunakan algoritma asimetris RSA, menjaga privasi dan keamanan data.
- **Autentikasi Pengguna**: Setiap pengguna harus memasukkan password untuk mengakses chat room.
- **Penyimpanan Pesan**: Pesan-pesan tersimpan pada file lokal agar dapat diakses kembali setelah aplikasi ditutup.

## Prasyarat

- **Python**: Versi 3.10 atau lebih tinggi
- **Library Standar**:
  - `socket`
  - `struct`
  - `threading`
  - `random`
  - `time`

## Instalasi dan Penggunaan

1. **Kloning Repositori**

   ```bash
   git clone https://github.com/username/repository-name.git
   cd repository-name
   ```

### Menjalankan Server

Pada perangkat yang akan dijadikan server, jalankan perintah berikut:

```bash
python server.py
```

Server akan meminta pengguna untuk memasukkan port (dalam rentang 1024-65535). Setelah server berjalan, ia akan menampilkan alamat IP dan port yang aktif.

### Menjalankan Client

Di perangkat lain yang terhubung dalam jaringan yang sama, jalankan client dengan:

```bash
python app.py
```

Client akan meminta alamat IP dan port server untuk koneksi. Setelah berhasil, client akan diminta memasukkan password dan username untuk bergabung ke chat room.

### Pengiriman Pesan dan File

Setelah berhasil masuk ke chat room, client dapat:

- Mengirim pesan teks langsung dengan mengetik pesan dan menekan Enter.
- Mengetik `/exit` untuk keluar dari chat room.

## Struktur Proyek

- `app.py` - Implementasi client dengan koneksi TCP over UDP dan enkripsi RSA.
- `server.py` - Server yang menerima pesan dari client, menyiarkan pesan, dan memproses otentikasi.
- `rsa.py` - Modul yang mengatur algoritma RSA untuk enkripsi dan dekripsi.
- `storage.py` - Modul untuk menyimpan dan memuat pesan lampau dari file `chat_log.txt`.

## Fitur Pada Aplikasi

- **Socket Programming**: Implementasi koneksi UDP dengan simulasi koneksi TCP.
- **Cryptography**: Enkripsi RSA untuk menjaga keamanan pesan.
- **Error Handling**: Checksum sederhana untuk memastikan integritas data pada saat transmisi.

## Kontributor

- **Kapal_Lawd**: [Arqila Surya Putra], [Daniel Sipayung]
- **Universitas**: Institut Teknologi Bandung (ITB)
