package main

import (
    "github.com/SAME1T/vpn-project/pkg/client"
    "fyne.io/fyne/v2/app"
    "fyne.io/fyne/v2/container"
    "fyne.io/fyne/v2/widget"
)

func main() {
    a := app.New()
    w := a.NewWindow("VPN Client")

    btnConnect := widget.NewButton("Bağlan", func() {
        client.Connect()
    })
    btnDisconnect := widget.NewButton("Bağlantıyı Kes", func() {
        client.Disconnect()
    })

    w.SetContent(container.NewVBox(
        btnConnect,
        btnDisconnect,
    ))
    w.ShowAndRun()
}