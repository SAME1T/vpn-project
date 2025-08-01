package protocol

import (
    "encoding/binary"
    "errors"
)

// Packet VPN protokol paketini temsil eder
type Packet struct {
    Type    byte   // Paket tipi (handshake, data, etc.)
    KeyID   uint8  // Anahtar kimliği
    Nonce   []byte // Şifreleme nonce'u
    Payload []byte // Şifrelenmiş veri
}

// Marshal paketi byte dizisine dönüştürür
func Marshal(pkt Packet) ([]byte, error) {
    if len(pkt.Nonce) > 255 {
        return nil, errors.New("nonce too long")
    }
    if len(pkt.Payload) > 65535 {
        return nil, errors.New("payload too long")
    }

    // Paket formatı:
    // [Type:1][KeyID:1][NonceLen:1][Nonce:NonceLen][PayloadLen:2][Payload:PayloadLen]
    data := make([]byte, 0, 5+len(pkt.Nonce)+len(pkt.Payload))
    
    // Type ve KeyID
    data = append(data, pkt.Type)
    data = append(data, pkt.KeyID)
    
    // Nonce uzunluğu ve Nonce
    data = append(data, byte(len(pkt.Nonce)))
    data = append(data, pkt.Nonce...)
    
    // Payload uzunluğu (2 byte) ve Payload
    payloadLen := make([]byte, 2)
    binary.BigEndian.PutUint16(payloadLen, uint16(len(pkt.Payload)))
    data = append(data, payloadLen...)
    data = append(data, pkt.Payload...)
    
    return data, nil
}

// Unmarshal byte dizisini pakete dönüştürür
func Unmarshal(data []byte) (Packet, error) {
    if len(data) < 5 {
        return Packet{}, errors.New("packet too short")
    }
    
    var pkt Packet
    offset := 0
    
    // Type ve KeyID
    pkt.Type = data[offset]
    offset++
    pkt.KeyID = data[offset]
    offset++
    
    // Nonce uzunluğu ve Nonce
    nonceLen := int(data[offset])
    offset++
    
    if offset+nonceLen > len(data) {
        return Packet{}, errors.New("invalid nonce length")
    }
    
    pkt.Nonce = make([]byte, nonceLen)
    copy(pkt.Nonce, data[offset:offset+nonceLen])
    offset += nonceLen
    
    // Payload uzunluğu
    if offset+2 > len(data) {
        return Packet{}, errors.New("invalid payload length header")
    }
    
    payloadLen := binary.BigEndian.Uint16(data[offset : offset+2])
    offset += 2
    
    // Payload
    if offset+int(payloadLen) > len(data) {
        return Packet{}, errors.New("invalid payload length")
    }
    
    pkt.Payload = make([]byte, payloadLen)
    copy(pkt.Payload, data[offset:offset+int(payloadLen)])
    
    return pkt, nil
}