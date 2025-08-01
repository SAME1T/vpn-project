package main

import (
	"fmt"
	"log"
	"net"

	"github.com/SAME1T/vpn-project/pkg/crypto"
)

func main() {
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

	buf := make([]byte, 1500)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("ReadFromUDP error: %v", err)
			continue
		}

		packet := buf[:n]
		if len(packet) < 12 {
			log.Printf("Packet too short: %d bytes", len(packet))
			continue
		}

		// İlk 12 byte nonce, geri kalanı ciphertext
		nonce := packet[:12]
		cipherText := packet[12:]

		// Decrypt
		pt, err := crypto.Decrypt(nonce, cipherText)
		if err != nil {
			log.Printf("Decrypt error: %v", err)
			continue
		}
		fmt.Printf("Gelen (decrypt): %s\n", string(pt))

		// "pong"u şifrele
		respNonce, respCipher, err := crypto.Encrypt([]byte("pong"))
		if err != nil {
			log.Printf("Encrypt error: %v", err)
			continue
		}
		respPacket := append(respNonce, respCipher...)

		// Geri yolla
		_, err = conn.WriteToUDP(respPacket, clientAddr)
		if err != nil {
			log.Printf("WriteToUDP error: %v", err)
		}
	}
}
