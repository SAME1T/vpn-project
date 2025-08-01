package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/SAME1T/vpn-project/pkg/crypto"
	"github.com/SAME1T/vpn-project/pkg/protocol"
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
	// TAP adapter'ı etkinleştir
	fmt.Println("TAP adapter'ı etkinleştiriliyor...")
	cmd := exec.Command("netsh", "interface", "set", "interface", "OpenVPN TAP-Windows6", "admin=enable")
	err := cmd.Run()
	if err != nil {
		log.Printf("TAP enable warning: %v", err)
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

				// Keepalive başlat (TUN olmadan)
				go keepalive(conn, clientAddr, &keyManager)
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
			fmt.Printf("Gelen (decrypt): %s\n", string(pt))

			// "pong" cevabını şifrele
			respNonce, respCipher, err := crypto.Encrypt(currentKey, []byte("pong"))
			if err != nil {
				log.Printf("Encrypt error: %v", err)
				continue
			}

			// Protocol paketine koy
			respPkt := protocol.Packet{
				Type:    1, // Data packet
				KeyID:   0,
				Nonce:   respNonce,
				Payload: respCipher,
			}

			respData, err := protocol.Marshal(respPkt)
			if err != nil {
				log.Printf("Marshal error: %v", err)
				continue
			}

			// Geri yolla
			_, err = conn.WriteToUDP(respData, clientAddr)
			if err != nil {
				log.Printf("WriteToUDP error: %v", err)
			}
		}
	}
}

// Keepalive mekanizması
func keepalive(conn *net.UDPConn, clientAddr *net.UDPAddr, keyManager *SharedKeyManager) {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Boş heartbeat paketi oluştur
		currentKey := keyManager.Get()
		nonce, ciphertext, err := crypto.Encrypt(currentKey, []byte("heartbeat"))
		if err != nil {
			log.Printf("Keepalive encrypt error: %v", err)
			continue
		}

		pkt := protocol.Packet{
			Type:    3, // Heartbeat packet
			KeyID:   0,
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
