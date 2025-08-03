package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/SAME1T/vpn-project/pkg/crypto"
	"github.com/SAME1T/vpn-project/pkg/protocol"
	"github.com/songgao/water"
)

func main() {
	fmt.Println("VPN Client başlatılıyor...")

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
	buf := make([]byte, 32)
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
	fmt.Println("Shared key türetildi")

	// TAP adapter varsa gerçek ağ trafiği başlat
	if tunIface != nil {
		fmt.Println("Gerçek ağ trafiği başlatılıyor...")
		go tunToUDP(tunIface, conn, sharedKey)
		go udpToTUN(conn, tunIface, sharedKey)
	} else {
		// Test mesajı gönder
		testMessage := []byte("Merhaba VPN Server!")
		nonce, ciphertext, err := crypto.Encrypt(sharedKey, testMessage)
		if err != nil {
			log.Fatalf("Encrypt failed: %v", err)
		}

		pkt := protocol.Packet{
			Nonce:   nonce,
			Payload: ciphertext,
		}

		data, err := protocol.Marshal(pkt)
		if err != nil {
			log.Fatalf("Marshal failed: %v", err)
		}

		_, err = conn.Write(data)
		if err != nil {
			log.Fatalf("Send failed: %v", err)
		}
		fmt.Println("Test mesajı gönderildi")

		// Echo cevabını al
		responseBuf := make([]byte, 1500)
		n, err = conn.Read(responseBuf)
		if err != nil {
			log.Fatalf("Response read failed: %v", err)
		}

		responsePkt, err := protocol.Unmarshal(responseBuf[:n])
		if err != nil {
			log.Fatalf("Response unmarshal failed: %v", err)
		}

		decrypted, err := crypto.Decrypt(sharedKey, responsePkt.Nonce, responsePkt.Payload)
		if err != nil {
			log.Fatalf("Response decrypt failed: %v", err)
		}

		fmt.Printf("Server'dan echo cevabı: %s\n", string(decrypted))
		fmt.Println("VPN bağlantısı başarılı!")
	}

	// Keepalive döngüsü
	for {
		time.Sleep(30 * time.Second)
		fmt.Println("Keepalive gönderiliyor...")

		keepaliveMsg := []byte("keepalive")
		nonce, ciphertext, err := crypto.Encrypt(sharedKey, keepaliveMsg)
		if err != nil {
			log.Printf("Keepalive encrypt failed: %v", err)
			continue
		}

		pkt := protocol.Packet{
			Nonce:   nonce,
			Payload: ciphertext,
		}

		data, err := protocol.Marshal(pkt)
		if err != nil {
			log.Printf("Keepalive marshal failed: %v", err)
			continue
		}

		_, err = conn.Write(data)
		if err != nil {
			log.Printf("Keepalive send failed: %v", err)
			break
		}
	}
}

// TUN'dan UDP'ye veri akışı
func tunToUDP(tunIface *water.Interface, conn *net.UDPConn, sharedKey []byte) {
	buf := make([]byte, 1500)
	for {
		n, err := tunIface.Read(buf)
		if err != nil {
			log.Printf("TUN read error: %v", err)
			continue
		}

		ipPacket := buf[:n]
		fmt.Printf("Client TUN'dan IP paketi alındı: %d bytes\n", len(ipPacket))

		// IP paketini şifrele
		nonce, ciphertext, err := crypto.Encrypt(sharedKey, ipPacket)
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
		_, err = conn.Write(data)
		if err != nil {
			log.Printf("UDP write error: %v", err)
		}
	}
}

// UDP'den TUN'a veri akışı
func udpToTUN(conn *net.UDPConn, tunIface *water.Interface, sharedKey []byte) {
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			continue
		}

		// Protocol paketi parse et
		pkt, err := protocol.Unmarshal(buf[:n])
		if err != nil {
			log.Printf("Unmarshal error: %v", err)
			continue
		}

		// Decrypt
		ipPacket, err := crypto.Decrypt(sharedKey, pkt.Nonce, pkt.Payload)
		if err != nil {
			log.Printf("Decrypt error: %v", err)
			continue
		}

		fmt.Printf("Client UDP'den IP paketi alındı: %d bytes\n", len(ipPacket))

		// TUN'a yaz
		_, err = tunIface.Write(ipPacket)
		if err != nil {
			log.Printf("TUN write error: %v", err)
		}
	}
}
