package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/SAME1T/vpn-project/pkg/crypto"
	"github.com/SAME1T/vpn-project/pkg/protocol"
)

func main() {
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:51820")
	if err != nil {
		log.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		log.Fatalf("DialUDP failed: %v", err)
	}
	defer conn.Close()

	// Handshake: Kendi key pair'ımızı oluştur
	ourPub, ourPriv, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Key generation failed: %v", err)
	}
	fmt.Println("Client key pair oluşturuldu")

	// Kendi public key'imizi server'a gönder
	_, err = conn.Write(ourPub)
	if err != nil {
		log.Fatalf("Public key send failed: %v", err)
	}
	fmt.Println("Client public key gönderildi")

	// Server'dan public key'i al
	buf := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("Server public key read failed: %v", err)
	}
	serverPub := buf[:n]
	fmt.Println("Server public key alındı")

	// Shared key türet
	sharedKey, err := crypto.DeriveSharedKey(ourPriv, serverPub)
	if err != nil {
		log.Fatalf("Shared key derivation failed: %v", err)
	}
	fmt.Println("Handshake tamamlandı, şifreli iletişim başlıyor")

	// Keepalive başlat
	go keepalive(conn, sharedKey)

	// Test için "ping"i şifrele
	nonce, ciphertext, err := crypto.Encrypt(sharedKey, []byte("ping"))
	if err != nil {
		log.Fatalf("Encrypt failed: %v", err)
	}

	// Protocol paketine koy
	pingPkt := protocol.Packet{
		Type:    1, // Data packet
		KeyID:   0,
		Nonce:   nonce,
		Payload: ciphertext,
	}

	pingData, err := protocol.Marshal(pingPkt)
	if err != nil {
		log.Fatalf("Marshal failed: %v", err)
	}

	_, err = conn.Write(pingData)
	if err != nil {
		log.Fatalf("Write failed: %v", err)
	}
	fmt.Println("Client gönderdi (encrypt): ping")

	// Şifreli cevabı oku ve aç
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = conn.Read(buf)
	if err != nil {
		log.Fatalf("Read failed: %v", err)
	}

	// Protocol paketi parse et
	respPkt, err := protocol.Unmarshal(buf[:n])
	if err != nil {
		log.Fatalf("Unmarshal failed: %v", err)
	}

	pong, err := crypto.Decrypt(sharedKey, respPkt.Nonce, respPkt.Payload)
	if err != nil {
		log.Fatalf("Decrypt failed: %v", err)
	}
	fmt.Println("Client aldı (decrypt):", string(pong))

	// Keepalive için sürekli dinle
	fmt.Println("Keepalive testine geçiyoruz...")
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			continue
		}

		pkt, err := protocol.Unmarshal(buf[:n])
		if err != nil {
			log.Printf("Unmarshal error: %v", err)
			continue
		}

		if pkt.Type == 3 { // Heartbeat
			pt, err := crypto.Decrypt(sharedKey, pkt.Nonce, pkt.Payload)
			if err != nil {
				log.Printf("Heartbeat decrypt error: %v", err)
				continue
			}
			fmt.Printf("Heartbeat alındı: %s\n", string(pt))
		}
	}
}

// Keepalive mekanizması
func keepalive(conn *net.UDPConn, sharedKey []byte) {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Boş heartbeat paketi oluştur
		nonce, ciphertext, err := crypto.Encrypt(sharedKey, []byte("heartbeat"))
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

		_, err = conn.Write(data)
		if err != nil {
			log.Printf("Keepalive send error: %v", err)
		} else {
			fmt.Println("Client keepalive gönderildi")
		}
	}
}
