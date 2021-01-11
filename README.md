# Final Projet IDS: Network Intrusion Detection using Maltrail to Detect Malicious Traffic
**Oleh:**
- Rindi Kartika Sari (05311840000013)

## Teori Singkat
Maltrail adalah **sistem deteksi lalu lintas berbahaya** _(malicious traffic detection system)_ dengan memanfaatkan daftar publik (hitam) yang berisi jalur berbahaya atau secara umum mencurigakan, bersama dengan jejak statis yang dikumpulkan dari berbagai laporan AV (Anti-Virus) dan daftar yang ditetapkan pengguna khusus (jejak tersebut dapat berupa nama domain, URL dan alamat IP).

### Arsitektur Maltrail
Maltrail didasarkan pada arsitektur **Traffic -> Sensor <-> Server <-> Client**.

![maltrail architecture](https://user-images.githubusercontent.com/49342639/103871816-1dfe7f80-5100-11eb-9400-dda86b847a07.png)

- **Sensor** adalah komponen mandiri yang berjalan pada node pemantau yang bertugas memantau lalu lintas yang lewat untuk jalur yang masuk daftar hitam (URL atau IP) pada jaringan. Sensor akan mengirimkan detail peristiwa ke server.
- **Server** merupakan komponen yang menyimpan semua peristiwa yang terjadi dalam periode (24 jam) dan memberikan data ke klien dalam potongan terkompresi dan diproses secara berurutan.
- **Klien** berupa _web browser_ dengan mengakses alamat IP dari HTTP server yang diberikan oleh server saat server dijalankan. Klien bertanggung jawab penuh atas bagian mempresentasikan detail peristiwa yang dikirimkan oleh server. 

## Gambaran Sistem Usulan

![gamb](https://user-images.githubusercontent.com/49342639/103879011-dc72d200-5109-11eb-8cb3-a2d06f77dde8.PNG)

Gambar tersebut menjelaskan bahwa sistem usulan dengan melalukan installasi sensor dan server pada laptop, kemudian sensor akan mendeteksi semua lalu lintas yang lewat ketika pengguna mengakses internet. Ketika lalu lintas berbahaya itu terdeteksi, maka sensor akan mengirimkan semua peristiwa yang terjadi kepada server dan server akan menyimpannya ke log. Lalu, server juga akan mengirimkan data peristiwa ke klien. Kemudian, klien akan menampilkan data peristiwa tersebut melalui _web browser_ dengan mengakses alamat IP dari HTTP server yaitu **http://0.0.0.0:8338**

## Pre-face
Hal yang perlu dipersiapkan sebelum mengeksekusi program maltrail, antara lain:
   
   | Software | Spesifikasi | Keterangan |
   | :---:  | :---:     | :---:   |
   | Linux  (Virtual Machine)    | Ubuntu 18.04      | Sensor, Server dan Klien     |
   | Python    | Python 2.7         | Bahasa pemrograman yang dipakai     |
   | Pcapy     | Modul ekstensi python         | Instalasi ```sudo apt install python-setuptools python-pcapy git```. Pcapy berfungsi menangkap paket pada jaringan     | 
   | Maltrail     | Default Spesifikasi       | Pemasangan ```git clone https://github.com/stamparm/maltrail.git```   

Adapun _configuration code_ yang perlu diperhatikan sebelum mengeksekusi program **maltrail** yaitu konfigurasi untuk **sensor** dan **server** yang berada pada file ```maltrail.conf```:
- **Konfigurasi Sensor**
  
  ![merge_from_ofoct](https://user-images.githubusercontent.com/49342639/104137838-5937d180-53d2-11eb-8eb6-6f7380922750.jpg)

  **Penjelasan**:

   - Konfigurasi **sensor** dapat ditemukan di dalam file ```maltrail.conf``` bagian [Sensor]:

      Proses **maltrail** hanya dijalankan pada 1 (satu) CPU Core saja.

      **Line 59**: Opsi ```USE_FEED_UPDATES``` dapat digunakan untuk mematikan pembaruan jejak _(trail)_

      **Line 71**: Opsi ```UPDATE_PERIOD``` berisi jumlah detik antara setiap pembaruan lintasan otomatis (**Note**: nilai default disetel ke 86400 = 1 hari)

      **Line 77**: Opsi ```CUSTOM_TRAILS_DIR```  dapat digunakan oleh pengguna untuk menyediakan lokasi direktori yang berisi file **trails** berekstensi ```(*.txt)``` 

      **Line 80**: Opsi ```CAPTURE_BUFFER``` menyajikan memori total (dalam byte persentase dari total memori fisik) yang akan digunakan dalam mode multiprosesing untuk menyimpan pengambilan paket dalam buffer untuk diproses lebih lanjut dengan proses non-capture

      **Line 83**: Opsi ```MONITOR_INTERFACE``` harus berisi nama antarmuka yang digunakan mengambil paket

      **Line 88**: Opsi ```CAPTURE_FILTER``` harus berisi tcpdumpfilter network capture ( ) untuk melewati paket yang tidak menarik dan memudahkan proses pengambilan paket

      **Line 91**: Opsi ```SENSOR_NAME``` berisi nama sensor yang menangkap suatu peristiwa lalu lintas berbahaya, sehingga kejadian dari satu sensor dapat dibedakan dari yang lain

      **Line 94-95**: Jika opsi ```LOG_SERVER``` disetel, maka semua peristiwa akan dikirim dari jarak jauh ke Server , jika tidak, mereka disimpan langsung ke direktori logging yang diatur dengan opsi ```LOG_DIR``` (line 130) 

      **Line 98**: Jika opsi ```SYSLOG_SERVER``` dan/atau ```LOGSTASH_SERVER``` disetel, maka dapat digunakan untuk mengirim peristiwa sensor (yaitu data log) ke server non-Maltrail

      **Line 104**: Jika opsi ```UPDATE_SERVER``` disetel, semua lintasan ditarik dari lokasi yang diberikan, jika tidak, lintasan sedang diperbarui dari definisi lintasan yang terletak di dalam instalasi itu sendiri

      **Line 107**: Opsi ```USE_HEURISTICS``` (line 107) mengaktifkan mekanisme **heuristik** (misalnya long domain name (suspicious), excessive no such domain name (suspicious), direct .exe download (suspicious), dll) yang berpotensi memperkenalkan aktivitas negatif yang memalsukan dirinya sebagai aktivitas positif


      Saat menjalankan **sensor** untuk pertama kali dan/atau setelah periode _non-running_ yang lebih lama, **sensor** akan secara otomatis memperbarui lintasan. Setelah inisialisasi, **sensor** akan mulai memantau antarmuka **enp0s3** yang dikonfigurasi (opsi MONITOR_INTERFACEdi dalam maltrail.conf) dan menulis peristiwa ke direktori **log** yang dikonfigurasi (opsi ```LOG_DIR``` di dalam bagian ```maltrail.conf```)

- **Konfigurasi Server**
  
  ![server](https://user-images.githubusercontent.com/49342639/104137887-b92e7800-53d2-11eb-8fc4-23714ab1efff.PNG)

  **Penjelasan**:
  
   - Konfigurasi **server** dapat ditemukan di dalam file ```maltrail.conf``` bagian [Server]:

      **Line 4**: Opsi ```HTTP_ADDRESS``` berisi alamat mendengarkan server web (**Note**: saya mengunakan 0.0.0.0 untuk mendengarkan di semua antarmuka)

      **Line 9**: Opsi ```HTTP_PORT``` berisi port mendengarkan server web. Port mendengarkan default diatur ke 8338 (port tcp/udp)

      **Line 12**: Jika opsi ```USE_SSL``` disetel ke **true**, maka SSL/TLS akan digunakan untuk mengakses server web

      **Line 21**: Sub-bagian ```USERS``` berisi pengaturan konfigurasi pengguna. Otentikasi pengguna terdiri dari **_username_**:```sha256(password)``` 

      **Line 48**: Opsi ```FAIL2BAN_REGEX``` berisi ekspresi reguler (misalnya attacker|reputation|potential[^"]*(web scan|directory traversal|injection|remote code)|spammer|mass scanner) untuk digunakan untuk ekstraksi IP sumber penyerang saat ini. Ini memungkinkan penggunaan mekanisme pemblokiran IP (misalnya fail2ban, iptablesatau ipset) dengan menarik alamat IP yang masuk daftar hitam secara berkala dari lokasi yang jauh


      Sama seperti **sensor**, saat menjalankan **server** untuk pertama kali dan/atau setelah periode _non-running_ yang lebih lama, **server** akan secara otomatis memperbarui lintasan. Kemudian, **server** menyimpan entri log di dalam direktori **log** yang dikonfigurasi (yaitu opsi ```LOG_DIR``` di dalam file ```maltrail.conf```) dan menyediakan antarmuka pelaporan web untuk menyajikan entri yang sama kepada pengguna akhir

## Demonstrasi
1. Memulai **sensor** maltrail dengan menjalankan ```sudo python sensor.py```
   
   ![01  sensor py_all](https://user-images.githubusercontent.com/49342639/104077009-88233b80-524a-11eb-8547-ccc392316db0.jpg)

2. Memulai **server** maltrail dengan menjalankan ```sudo python server.py```
   
   ![02  server py](https://user-images.githubusercontent.com/49342639/104077058-b0129f00-524a-11eb-92dd-056be2cceae5.png)

   Setelah kita menjalankan server maltrail, server menunjukkan bahwa alamat IP untuk **HTTP Server** adalah **http://0.0.0.0:8338/**

3. Dari alamat IP untuk HTTP Server yang telah kita dapatkan pada langkah (2), maka kita dapat membuka alamat IP tersebut di _web browser_.
Ketika pertama kali membuka alamat IP HTTP Server tersebut, kita akan diminta untuk melakukan **otentikasi** terlebih dahulu dengan memasukkan _username_ dan _password_  yang telah ditetapkan oleh administrator server di dalam file konfigurasi ```maltrail.conf```.

    ![03  otentikasi](https://user-images.githubusercontent.com/49342639/104077101-db958980-524a-11eb-8622-d1691e1fb178.png)

4. Setelah **otentikasi** berhasil, kita akan disajikan dengan **antarmuka data pelaporan peristiwa** yang berhasil ditangkap oleh **sensor** dan disimpan oleh **server**
    
    ![04  otentikasi berhasil](https://user-images.githubusercontent.com/49342639/104077209-5c548580-524b-11eb-8ce3-0ce5a3002a1e.png)

## Pengujian Pertama - _Conficker_ (Malware)
Pengujian pertama yaitu menguji lalu lintas pada suatu _IP Address_ **136.161.101.53** yang menanam sebuah _conficker_ dengan jenis **Sinkhole**.
   
   a. Hal ini dilakukan dengan terlebih dahulu menjalankan ```ping 136.161.101.53```

   ![05  ping 136 161 101 53 (sinkhole malware)](https://user-images.githubusercontent.com/49342639/104078008-82c7f000-524e-11eb-9be4-f8aa724d63a9.png)

   b. Kemudian, kita dapat melakukan pengecekan apakah ada  peristiwa yang tertangkap oleh **sensor** yang disimpan oleh **server** dengan meninjau **log maltrail** pada perintah ```cat /var/log/maltrail/$(date +"%Y-%m-%d").log```

   ![06  log (5)](https://user-images.githubusercontent.com/49342639/104078155-3fba4c80-524f-11eb-91c8-0d23d8141cd1.png)

   Dapat kita lihat bahwa terdapat peristiwa yang tertangkap oleh **sensor** dan berhasil disimpan oleh **server**. 
   
   c. Untuk lebih mudah memahami data peristiwa yang tercatat oleh **server**, maka kita bisa me-_refresh_ **F5** antarmuka data pelaporan peristiwa yang sudah kita buka di _web browser_ pada langkah (4)

   ![07  maltrail (5 _ 6)](https://user-images.githubusercontent.com/49342639/104078291-e3a3f800-524f-11eb-870d-d2cdd7a1ee26.png)

   Dari data pelaporan peristiwa yang kita lihat pada antarmuka di atas menunjukkan bahwa pada ```dst_ip: 136.161.101.53``` _destination IP_ tercatat ```trail: 136.161.101.53``` jejak dari IP tersebut terdapat sebuah ```info: sinkhole conficker(malware)``` _conficker_ berjenis **Sinkhole** yang membawa ```severity: high``` dampak sangat besar.

## Pengujian Kedua - Andromeda (Malware)
Pengujian kedua yaitu menguji penangkapan lalu lintas **DNS** berdomain **morped.ru** yang menanam sebuah Trojan Malware dengan jenis **Andromeda**.  
   
  a. Untuk dapat menguji lalu lintas **DNS** tersebut, kita dapat menanyakan catatan **DNS** untuk domain **morphed.ru** sehingga memungkinkan kita untuk melihat beberaoa catatan DNS tersebut dengan menjalankan ```nslookup morphed.ru```

   ![08  nslookup morped_ru](https://user-images.githubusercontent.com/49342639/104093167-5e562d00-52bb-11eb-8e13-62175238fe1d.png)
    
   b. Lalu, kita lakukan pengecekan **log** maltrail untuk melihat apakah ada data peristiwa yang tercatat oleh **server** dari pengujian kedua dengan menjalankan ```cat /var/log/maltrail/$(date +"%Y-%m-%d").log```
   
   ![09  log (8)](https://user-images.githubusercontent.com/49342639/104093232-c4db4b00-52bb-11eb-8398-2f41708701f1.png)
    
   Dari **log** menunjukkan bahwa dari **sensor** berhasil mendeteksi sebuah ancaman dan menyimpan peristiwa yang terdeteksi tersebut di **server**. Ancaman peristiwa yang terdeteksi dari pengujian lalu lintas **DNS** ini adalah adanya sebuah ancaman trojan malware berjenis **Andromeda**.
    
   c. Untuk lebih mudah memahami data peristiwa yang tercatat oleh **server**, maka kita bisa me-_refresh_ **F5** antarmuka data pelaporan peristiwa yang sudah kita buka di _web browser_ pada langkah (4)

   ![10  maltrail (8 _ 9)](https://user-images.githubusercontent.com/49342639/104093384-d3763200-52bc-11eb-8400-eb57196ce655.png)

   Dari data pelaporan peristiwa yang kita lihat pada antarmuka di atas menunjukkan bahwa pada ```dst_ip: 136.161.101.53``` _destination IP_ (_IP Address_ DNS) tercatat ```trail: morphed.ru``` jejak dari **DNS** berdomain **morphed.ru** tersebut terdapat sebuah ```info: andromeda(malware)``` trojan malware berjenis **Andromeda** yang membawa ```severity: high``` dampak sangat besar.

## Pengujian Ketiga - Metode Nmap
Pengujian ketiga akan terbagi menjadi 2 (dua) bagian, antara lain:
- Penangkapan lalu lintas dari jaringan lokal lain
- Penangkapan lalu lintas _IP Address_ bebas

1) **Pengujian Ketiga Bagian A - Penangkapan lalu lintas dari jaringan lokal lain**
   
   Pengujian ketiga bagian A berfokus pada penangkapan lalu lintas **jaringan lokal lain** yang terhubung dengan _interface_ dari sistem Operasi **Ubuntu** yang saya gunakan.

   a. Untuk melakukan pengujian ini, maka terlebih dahulu kita melakukan pengecekan _IP Address_ dari sistem operasi **Ubuntu** dengan menjalankan ```ifconfig``` pada terminal sistem operasi **Ubuntu**

   ![11  ifconfig linux](https://user-images.githubusercontent.com/49342639/104094393-45517a00-52c3-11eb-8211-e10c3371b139.png)

   Dari hasil pengecekan _IP Address_ tersebut dapat dilihat bahwa _interface_ **enp0s3** memiliki _IP Address_ **192.168.43.162**

   b. Selain itu, kita juga melakukan pengecekan _IP Address_ dari jaringan lokal lain (disini saya menggunakan sistem operasi **Windows**). Sehingga, kita dapat menjalankan ```ipconfig``` pada _command prompt_ milik sistem operasi **Windows**

   ![12  ipconfig windows](https://user-images.githubusercontent.com/49342639/104094533-0839b780-52c4-11eb-9633-4e9b23b85f4b.PNG)

   Dari hasil pengecekan _IP Address__ tersebut dapat dilihat bahwa _interface_ **Windows** yang terhubung dengan **Ubuntu** yaitu **Wireless LAN adapter Wi-Fi** memiliki _IP Address_ **192.168.43.180**

   c. Setelah mengecek _IP Address_ dari kedua buah sistem operasi, selanjutnya kita dapat memulai untuk menangkap lalu lintas dari jaringan lokal **Windows** dengan menjalankan ```sudo nmap -A --script=vuln 192.168.43.180``` di terminal **Ubuntu**

   ![13  vuln windows](https://user-images.githubusercontent.com/49342639/104094691-04f2fb80-52c5-11eb-9a21-30fb7f67f242.png)

   Sembari menjalankan **nmap**, kita juga melakukan ```ping 192.167.43.162``` di _command prompt_ **Windows** 

   ![14  ping 192 168 43 162 (linux)](https://user-images.githubusercontent.com/49342639/104094631-a6c61880-52c4-11eb-9061-20ae14145a30.PNG)

   d. Untuk mengetahui apakah ada peristiwa yang terdeteksi oleh **sensor** dari pengujian ini, maka kita kita bisa me-_refresh_ **F5** antarmuka data pelaporan peristiwa yang sudah kita buka di _web browser_ pada langkah (4)

   ![15  maltrail (13 _ 14)](https://user-images.githubusercontent.com/49342639/104094800-b2660f00-52c5-11eb-87ae-51e23d7d9fde.png)

   Dari data pelaporan peristiwa yang kita lihat pada antarmuka di atas menunjukkan bahwa terdapat sebuah ancaman ```info: potential port scanning``` pemindaian port dengan ```severity: low``` tingkat rendah apabila terdapat jaringan lokal yang terhubung dengan _interface_ terbuka.

2) **Pengujian Ketiga Bagian B - Penangkapan lalu lintas _IP Address_ bebas**
   
   Pengujian ketiga bagian B berfokus pada penangkapan lalu lintas dari sebuah _IP Address_ bebas (disini saya menguji _IP Address_ **131.107.1.254**)

   a. Untuk melakukan pengujian ini, kita dapat memulai untuk menangkap lalu lintas dari _IP Address_ **131.107.1.254** dengan menjalankan ```sudo nmap -n --script=vuln 131.107.1.254``` di terminal **Ubuntu**

   ![16  vuln 131 107 1 254 (yt bapak botak)](https://user-images.githubusercontent.com/49342639/104095275-944dde00-52c8-11eb-8b74-ad7f467f642d.png)

   b. Untuk mengetahui apakah ada peristiwa yang terdeteksi oleh **sensor** dari pengujian ini, maka kita kita bisa me-_refresh_ **F5** antarmuka data pelaporan peristiwa yang sudah kita buka di _web browser_ pada langkah (4)

   ![17  maltrail (16)](https://user-images.githubusercontent.com/49342639/104095299-b2b3d980-52c8-11eb-8e1c-5860b7bab53d.png)

   Dari data pelaporan peristiwa yang kita lihat pada antarmuka di atas menunjukkan bahwa terdapat **8** ancaman dengan jenis ancaman yang berbeda-beda. Kedelapan ancaman tersebut ```severity: medium``` merupakan ancaman tingkat medium.
