package client

import (
	"fmt"
	"log"
)

// VPN bağlantı durumu
var isConnected bool = false

// Connect VPN bağlantısını başlatır
func Connect() error {
	if isConnected {
		return fmt.Errorf("VPN zaten bağlı")
	}
	
	// Burada gerçek VPN bağlantı kodu olacak
	// Şimdilik basit bir simülasyon
	log.Println("VPN bağlantısı başlatılıyor...")
	
	// TODO: Gerçek VPN client kodunu buraya ekle
	// Örnek: cmd/client/main.go içindeki bağlantı mantığını kullan
	
	isConnected = true
	log.Println("VPN başarıyla bağlandı")
	return nil
}

// Disconnect VPN bağlantısını keser
func Disconnect() error {
	if !isConnected {
		return fmt.Errorf("VPN zaten bağlı değil")
	}
	
	log.Println("VPN bağlantısı kesiliyor...")
	
	// TODO: Gerçek VPN disconnect kodunu buraya ekle
	
	isConnected = false
	log.Println("VPN bağlantısı başarıyla kesildi")
	return nil
}

// IsConnected VPN bağlantı durumunu döndürür
func IsConnected() bool {
	return isConnected
}