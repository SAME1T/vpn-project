package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/SAME1T/vpn-project/pkg/crypto"
	"github.com/SAME1T/vpn-project/pkg/protocol"
	"github.com/songgao/water"
)

// Thread-safe shared key yönetimi
type SharedKeyManager struct {
	mu  sync.RWMutex
	key []byte
}

func (s *SharedKeyManager) Set(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key = make([]byte, len(key))
	copy(s.key, key)
}

func (s *SharedKeyManager) Get() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := make([]byte, len(s.key))
	copy(key, s.key)
	return key
}

func main() {
	fmt.Println("VPN Server başlatılıyor...")
	
	// TAP adapter oluşturmayı dene
	var tunIface *water.Interface
	config := water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID: "tap0901",
			Network:     "OpenVPN TAP-Windows6",
		},
	}
	
	tunIface, err := water.New(config)
	if err != nil {
		fmt.Printf("TAP adapter oluşturulamadı: %v\n", err)
		fmt.Println("UDP echo modunda çalışacak...")
		tunIface = nil
	} else {
		defer tunIface.Close()
		fmt.Printf("TAP arayüzü oluşturuldu: %s\n", tunIface.Name())
	}

	addr, err := net.ResolveUDPAddr("udp", ":51820")
	if err != nil {
		log.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()
	fmt.Println("Server dinliyor:", addr.String())

	// Handshake: Kendi key pair'ımızı oluştur
	ourPub, ourPriv, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Key generation failed: %v", err)
	}
	fmt.Println("Server key pair oluşturuldu")

	var keyManager SharedKeyManager
	var clientAddr *net.UDPAddr
	handshakeCompleted := false

	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("ReadFromUDP error: %v", err)
			continue
		}

		if !handshakeCompleted {
			// Handshake aşaması
			if clientAddr == nil {
				// İlk bağlantı - client public key'ini al
				clientPub := buf[:n]
				fmt.Println("Client public key alındı")

				// Kendi public key'imizi gönder
				_, err = conn.WriteToUDP(ourPub, addr)
				if err != nil {
					log.Printf("Public key send error: %v", err)
					continue
				}
				fmt.Println("Server public key gönderildi")

				// Shared key türet
				sharedKey, err := crypto.DeriveSharedKey(ourPriv, clientPub)
				if err != nil {
					log.Printf("Shared key derivation failed: %v", err)
					continue
				}
				keyManager.Set(sharedKey)

				clientAddr = addr
				handshakeCompleted = true
				fmt.Println("Handshake tamamlandı, şifreli iletişim başlıyor")

				// TAP adapter varsa gerçek ağ trafiği başlat
				if tunIface != nil {
					go tunToUDP(tunIface, conn, clientAddr, &keyManager)
					go udpToTUN(conn, tunIface, clientAddr, &keyManager)
				}
				
				// Keepalive başlat
				go keepalive(conn, clientAddr, &keyManager)
				go keyRotation(conn, clientAddr, ourPriv, clientPub, &keyManager)
				continue
			}
		}

		// Şifreli veri iletişimi
		if handshakeCompleted && addr.String() == clientAddr.String() {
			// Protocol paketi parse et
			pkt, err := protocol.Unmarshal(buf[:n])
			if err != nil {
				log.Printf("Unmarshal error: %v", err)
				continue
			}

			// Decrypt
			currentKey := keyManager.Get()
			pt, err := crypto.Decrypt(currentKey, pkt.Nonce, pkt.Payload)
			if err != nil {
				log.Printf("Decrypt error: %v", err)
				continue
			}

			if tunIface != nil {
				// Gerçek ağ trafiği - TAP'a yaz
				_, err = tunIface.Write(pt)
				if err != nil {
					log.Printf("TAP write error: %v", err)
				} else {
					fmt.Printf("TAP'a IP paketi yazıldı: %d bytes\n", len(pt))
				}
			} else {
				// Echo modu - test mesajını geri gönder
				nonce, ciphertext, err := crypto.Encrypt(currentKey, pt)
				if err != nil {
					log.Printf("Encrypt error: %v", err)
					continue
				}

				pktResponse := protocol.Packet{
					Nonce:   nonce,
					Payload: ciphertext,
				}

				responseData, err := protocol.Marshal(pktResponse)
				if err != nil {
					log.Printf("Marshal error: %v", err)
					continue
				}

				_, err = conn.WriteToUDP(responseData, addr)
				if err != nil {
					log.Printf("WriteToUDP error: %v", err)
				}

				fmt.Printf("Echo paketi gönderildi: %d bytes\n", len(responseData))
			}
		}
	}
}

// TUN'dan UDP'ye veri akışı
func tunToUDP(tunIface *water.Interface, conn *net.UDPConn, clientAddr *net.UDPAddr, keyManager *SharedKeyManager) {
	buf := make([]byte, 1500)
	for {
		n, err := tunIface.Read(buf)
		if err != nil {
			log.Printf("TUN read error: %v", err)
			continue
		}

		ipPacket := buf[:n]
		fmt.Printf("TUN'dan IP paketi alındı: %d bytes\n", len(ipPacket))

		// IP paketini şifrele
		currentKey := keyManager.Get()
		nonce, ciphertext, err := crypto.Encrypt(currentKey, ipPacket)
		if err != nil {
			log.Printf("Encrypt error: %v", err)
			continue
		}

		// Protocol paketine koy
		pkt := protocol.Packet{
			Nonce:   nonce,
			Payload: ciphertext,
		}

		data, err := protocol.Marshal(pkt)
		if err != nil {
			log.Printf("Marshal error: %v", err)
			continue
		}

		// UDP'ye gönder
		_, err = conn.WriteToUDP(data, clientAddr)
		if err != nil {
			log.Printf("UDP write error: %v", err)
		}
	}
}

// UDP'den TUN'a veri akışı
func udpToTUN(conn *net.UDPConn, tunIface *water.Interface, clientAddr *net.UDPAddr, keyManager *SharedKeyManager) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			continue
		}

		// Sadece bilinen client'tan gelen paketleri işle
		if addr.String() != clientAddr.String() {
			continue
		}

		// Protocol paketi parse et
		pkt, err := protocol.Unmarshal(buf[:n])
		if err != nil {
			log.Printf("Unmarshal error: %v", err)
			continue
		}

		// Decrypt
		currentKey := keyManager.Get()
		ipPacket, err := crypto.Decrypt(currentKey, pkt.Nonce, pkt.Payload)
		if err != nil {
			log.Printf("Decrypt error: %v", err)
			continue
		}

		fmt.Printf("UDP'den IP paketi alındı: %d bytes\n", len(ipPacket))

		// TUN'a yaz
		_, err = tunIface.Write(ipPacket)
		if err != nil {
			log.Printf("TUN write error: %v", err)
		}
	}
}

// Keepalive mekanizması
func keepalive(conn *net.UDPConn, clientAddr *net.UDPAddr, keyManager *SharedKeyManager) {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		currentKey := keyManager.Get()
		nonce, ciphertext, err := crypto.Encrypt(currentKey, []byte("heartbeat"))
		if err != nil {
			log.Printf("Keepalive encrypt error: %v", err)
			continue
		}

		pkt := protocol.Packet{
			Nonce:   nonce,
			Payload: ciphertext,
		}

		data, err := protocol.Marshal(pkt)
		if err != nil {
			log.Printf("Keepalive marshal error: %v", err)
			continue
		}

		_, err = conn.WriteToUDP(data, clientAddr)
		if err != nil {
			log.Printf("Keepalive send error: %v", err)
		} else {
			fmt.Println("Server keepalive gönderildi")
		}
	}
}

// Key rotation mekanizması
func keyRotation(conn *net.UDPConn, clientAddr *net.UDPAddr, ourPriv, clientPub []byte, keyManager *SharedKeyManager) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Yeni shared key türet
		sharedKey, err := crypto.DeriveSharedKey(ourPriv, clientPub)
		if err != nil {
			log.Printf("Key rotation failed: %v", err)
			continue
		}

		keyManager.Set(sharedKey)
		fmt.Println("Key rotated")
	}
}
