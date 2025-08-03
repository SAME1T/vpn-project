package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\n=== VPN Control Panel ===")
		fmt.Println("1. VPN Client Başlat")
		fmt.Println("2. VPN Server Başlat")
		fmt.Println("3. TAP Driver Kurulum Talimatları")
		fmt.Println("4. Çıkış")
		fmt.Print("Seçiminizi yapın (1-4): ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			fmt.Println("\nÇalıştırılacak komut:")
			fmt.Println("go run cmd/client/main.go")
			fmt.Println("\nBu komutu yeni bir terminal penceresinde çalıştırın.")
		case "2":
			fmt.Println("\nÇalıştırılacak komut:")
			fmt.Println("go run cmd/server/main.go")
			fmt.Println("\nBu komutu yeni bir terminal penceresinde çalıştırın.")
			fmt.Println("\n⚠️  Not: Eğer TAP driver hatası alırsanız, seçenek 3'ü seçin.")
		case "3":
			fmt.Println("\n=== TAP Driver Kurulum Talimatları ===")
			fmt.Println("1. OpenVPN'yi indirin: https://openvpn.net/community-downloads/")
			fmt.Println("2. OpenVPN'yi yükleyin (TAP driver otomatik kurulacak)")
			fmt.Println("3. Bilgisayarı yeniden başlatın")
			fmt.Println("4. PowerShell'i Yönetici olarak çalıştırın")
			fmt.Println("5. Şu komutları çalıştırın:")
			fmt.Println("   Enable-NetAdapter -Name 'OpenVPN TAP-Windows6' -Confirm:$false")
			fmt.Println("6. Tekrar deneyin")
			fmt.Println("\nAlternatif: Windows için TAP driver'ı manuel kurun")
			fmt.Println("\nNot: TAP adapter olmadan VPN sadece test modunda çalışır.")
			fmt.Println("Gerçek ağ trafiği yönlendirmesi için TAP adapter gerekli.")
		case "4":
			fmt.Println("Çıkılıyor...")
			return
		default:
			fmt.Println("Geçersiz seçim! Lütfen 1, 2, 3 veya 4 girin.")
		}

		fmt.Print("\nDevam etmek için Enter'a basın...")
		reader.ReadString('\n')
	}
}
