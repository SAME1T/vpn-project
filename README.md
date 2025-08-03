# 🚀 Advanced VPN Project

Bu proje, modern kriptografi teknikleri kullanarak sıfırdan geliştirilmiş tam fonksiyonel bir VPN (Virtual Private Network) uygulamasıdır.

## 👨‍💻 Geliştirici
**Samet Çiftci**  
📧 Email: scsametciftci@gmail.com  
🔗 GitHub: [@SAME1T](https://github.com/SAME1T)

## 🔥 Özellikler

### 🔐 Güvenlik Katmanları
- **X25519 Elliptic Curve Diffie-Hellman**: Modern anahtar değişim protokolü
- **AES-256-GCM**: End-to-end şifreleme ve doğrulama
- **Random Nonce**: Her paket için benzersiz şifreleme parametresi
- **Thread-Safe Key Management**: Güvenli anahtar yönetimi

### 🌐 Network Özellikleri
- **UDP Tabanlı İletişim**: Yüksek performans için UDP protokolü
- **Binary Protocol**: Verimli paket serileştirme
- **TUN/TAP Interface Desteği**: Virtual network interface entegrasyonu
- **Keepalive Sistemi**: 25 saniyelik heartbeat ile bağlantı kontrolü

### ⚡ Gelişmiş Özellikler
- **Otomatik Anahtar Yenileme**: Saatlik key rotation
- **Multi-Threading**: Eşzamanlı veri işleme
- **Packet Type Management**: Farklı paket türleri (Handshake, Data, Heartbeat, Key Rotation)
- **Error Handling**: Kapsamlı hata yönetimi

## 🏗️ Proje Yapısı

```
vpn-project/
├── cmd/
│   ├── server/main.go          # VPN Server (TUN destekli)
│   ├── client/main.go          # VPN Client (TUN destekli)
│   ├── server-simple/main.go   # Basit VPN Server (TUN olmadan)
│   ├── client-simple/main.go   # Basit VPN Client (TUN olmadan)
│   ├── server-tap/main.go      # TAP specific server
│   └── server-manual/main.go   # Manuel TAP implementation
├── pkg/
│   ├── crypto/
│   │   ├── crypto.go           # AES-GCM şifreleme fonksiyonları
│   │   └── handshake.go        # X25519 anahtar değişimi
│   └── protocol/
│       └── protocol.go         # Binary paket protokolü
├── go.mod                      # Go module dependencies
├── go.sum                      # Dependency checksums
└── README.md                   # Bu dosya
```

## 🛠️ Teknik Detaylar

### Kriptografi Implementasyonu

#### X25519 Anahtar Değişimi
```go
// Anahtar çifti oluşturma
public, private, err := crypto.GenerateKeyPair()

// Paylaşılan secret türetme
sharedKey, err := crypto.DeriveSharedKey(ourPriv, theirPub)
```

#### AES-GCM Şifreleme
```go
// Şifreleme (dinamik nonce ile)
nonce, ciphertext, err := crypto.Encrypt(sharedKey, plaintext)

// Deşifreleme
plaintext, err := crypto.Decrypt(sharedKey, nonce, ciphertext)
```

### Protocol Yapısı

Her VPN paketi şu yapıda:
```
[Type:1][KeyID:1][NonceLen:1][Nonce:N][PayloadLen:2][Payload:M]
```

**Paket Türleri:**
- `Type 0`: Handshake paketi
- `Type 1`: Normal veri paketi  
- `Type 2`: IP veri paketi (TUN)
- `Type 3`: Heartbeat paketi
- `Type 4`: Anahtar yenileme paketi

### Thread-Safe Key Management

```go
type SharedKeyManager struct {
    mu  sync.RWMutex
    key []byte
}

func (s *SharedKeyManager) Set(key []byte) { /* Thread-safe set */ }
func (s *SharedKeyManager) Get() []byte { /* Thread-safe get */ }
```

## 🚀 Kurulum ve Çalıştırma

### Gereksinimler
- Go 1.19+
- Windows: TAP-Windows driver (OpenVPN ile birlikte)
- Linux: TUN/TAP kernel desteği

### Bağımlılıkları Yükleyin
```bash
go mod download
```

### Basit Test (TUN olmadan)

**1. Server'ı başlatın:**
```bash
go run cmd/server-simple/main.go
```

**2. Client'ı başlatın (yeni terminal):**
```bash
go run cmd/client-simple/main.go
```

**Beklenen çıktı:**
```
✅ X25519 handshake tamamlandı
✅ AES-GCM şifreleme başarılı
✅ Ping-pong mesajlaşması
✅ Keepalive sistemi aktif
```

### Tam VPN Test (TUN ile)

**Windows'ta TAP driver kurulumu:**
1. [OpenVPN](https://openvpn.net/community-downloads/) indirin ve kurun
2. Yönetici olarak PowerShell açın

**Server:**
```bash
go run cmd/server/main.go
```

**Client:**
```bash
go run cmd/client/main.go
```

## 📊 Performans Özellikleri

- **Handshake Süresi**: ~5ms (local)
- **Şifreleme Hızı**: AES-GCM hardware acceleration
- **Throughput**: UDP buffer size 1500 bytes
- **Keepalive Interval**: 25 saniye
- **Key Rotation**: 1 saat (yapılandırılabilir)

## 🔬 Test Senaryoları

### 1. Kriptografi Testi
- X25519 anahtar değişimi doğrulaması
- AES-GCM şifreleme/deşifreleme testi
- Random nonce üretimi kontrolü

### 2. Protocol Testi
- Binary paket serileştirme/deserileştirme
- Farklı paket türlerinin işlenmesi
- Hatalı paket handling

### 3. Network Testi
- UDP packet delivery
- Keepalive mekanizması
- Connection state management

## 🔧 Geliştirme Notları

### Key Rotation Implementasyonu
```go
func keyRotation(conn *net.UDPConn, clientAddr *net.UDPAddr, 
                ourPriv, clientPub []byte, keyManager *SharedKeyManager) {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()

    for range ticker.C {
        // Yeni anahtar çifti oluştur
        newPub, newPriv, err := crypto.GenerateKeyPair()
        
        // Yeni shared key türet
        newSharedKey, err := crypto.DeriveSharedKey(newPriv, clientPub)
        
        // Thread-safe key update
        keyManager.Set(newSharedKey)
    }
}
```

### TUN Interface Yönetimi
```go
// TUN → UDP veri akışı
func tunToUDP(tunIface *water.Interface, conn *net.UDPConn, 
              clientAddr *net.UDPAddr, keyManager *SharedKeyManager) {
    for {
        // TUN'dan IP paketi oku
        ipPacket := readFromTUN(tunIface)
        
        // Şifrele ve UDP'ye gönder
        encryptedPacket := encrypt(ipPacket, keyManager.Get())
        sendToUDP(conn, encryptedPacket, clientAddr)
    }
}
```

## 🌟 Gelecek Geliştirmeler

- [ ] **Multi-Client Support**: Birden fazla client desteği
- [ ] **Load Balancing**: Trafiği dengeleme
- [ ] **Compression**: Veri sıkıştırma
- [ ] **Bandwidth Limiting**: Bant genişliği kontrolü
- [ ] **Logging System**: Detaylı loglama
- [ ] **Configuration File**: YAML/JSON config
- [ ] **Docker Support**: Containerization
- [ ] **Metrics & Monitoring**: Prometheus/Grafana entegrasyonu

## 📝 Lisans

Bu proje MIT lisansı altında geliştirilmiştir.

## 🤝 Katkıda Bulunma

1. Projeyi fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişiklikleri commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'i push edin (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun

## 📞 İletişim

Herhangi bir soru veya geri bildirim için:

📧 **Email**: scsametciftci@gmail.com  
🔗 **GitHub**: [@SAME1T](https://github.com/SAME1T)  
💼 **LinkedIn**: [Samet Çiftçi](https://linkedin.com/in/sametciftci)

---

⚡ **Made with ❤️ by Samet Çiftçi** ⚡