# Sistem Autentikasi Backend

Sistem autentikasi RESTful API yang dibangun dengan Go Fiber untuk menangani registrasi dan login pengguna dengan autentikasi JWT.

## Fitur

- Registrasi pengguna dengan enkripsi password
- Login pengguna dengan generasi token JWT
- Validasi password
- Pengecekan username unik
- Validasi input

## Teknologi yang Digunakan

- Go (Golang)
- MySQL Database
- Framework Fiber
- GORM (ORM)
- JWT untuk Autentikasi

## Cara Instalasi

1. Clone repository
```bash
git clone <url-repository>
```

2. Install dependencies
```bash
go mod download
```

3. Sesuaikan konfigurasi database di file .env

4. Jalankan aplikasi
```bash
go run main.go
```

## API Endpoints

### Register

POST /register

Request Body:
```json
{
    "username": "contoh_user",
    "password": "password123"
}
```

Response:
```json
{
    "message": "User berhasil dibuat",
    "status": 200,
    "data": {
        "id": 1,
        "username": "contoh_user"
    }
}
```

### Login

POST /login

Request Body:
```json
{
    "username": "contoh_user",
    "password": "password123"
}
```

Response:
```json
{
    "message": "Login berhasil",
    "status": 200,
    "data": {
        "id": 1,
        "username": "contoh_user"
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

## Aturan Validasi

### Username:
- Tidak boleh mengandung spasi
- Harus unik dalam sistem
- Tidak boleh kosong

### Password:
- Minimal 8 karakter
- Tidak boleh kosong

## Keamanan

- Password di-hash menggunakan bcrypt
- Menggunakan JWT untuk sesi autentikasi
- Token kadaluarsa setelah 1 jam

## Penanganan Error

API akan mengembalikan kode status HTTP yang sesuai:

- 400 Bad Request - Data input tidak valid
- 401 Unauthorized - Kredensial tidak valid
- 500 Internal Server Error - Error pada server

## Catatan Penting

Untuk penggunaan di production:
- Ganti JWT secret key dengan environment variable
- Konfigurasi CORS dengan benar
- Implementasi rate limiting
- Tambahkan pengamanan tambahan

## Lisensi

[MIT License](LICENSE)