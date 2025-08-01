package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/SAME1T/vpn-project/pkg/crypto"
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

	// "ping"i şifrele
	nonce, ciphertext, err := crypto.Encrypt([]byte("ping"))
	if err != nil {
		log.Fatalf("Encrypt failed: %v", err)
	}
	pingPacket := append(nonce, ciphertext...)
	_, err = conn.Write(pingPacket)
	if err != nil {
		log.Fatalf("Write failed: %v", err)
	}
	fmt.Println("Client gönderdi (encrypt): ping")

	// Şifreli cevabı oku ve aç
	buf := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		log.Fatalf("Read failed: %v", err)
	}

	packet := buf[:n]
	if len(packet) < 12 {
		log.Fatalf("Packet too short: %d bytes", len(packet))
	}

	// İlk 12 byte nonce, geri kalanı ciphertext
	respNonce := packet[:12]
	respCiphertext := packet[12:]

	pong, err := crypto.Decrypt(respNonce, respCiphertext)
	if err != nil {
		log.Fatalf("Decrypt failed: %v", err)
	}
	fmt.Println("Client aldı (decrypt):", string(pong))
}
