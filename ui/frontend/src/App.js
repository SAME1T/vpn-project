import React, { useState } from 'react';
import './App.css';

function App() {
  const [status, setStatus] = useState('disconnected'); // 'connected', 'disconnected', 'loading'
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState(''); // 'success', 'error'

  const handleConnect = async () => {
    setStatus('loading');
    setMessage('VPN bağlantısı kuruluyor...');
    setMessageType('');

    try {
      const response = await fetch('/api/connect', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const data = await response.json();
      
      if (data.success) {
        setStatus('connected');
        setMessage(data.message);
        setMessageType('success');
      } else {
        setStatus('disconnected');
        setMessage(data.message);
        setMessageType('error');
      }
    } catch (error) {
      setStatus('disconnected');
      setMessage('Bağlantı hatası: ' + error.message);
      setMessageType('error');
    }
  };

  const handleDisconnect = async () => {
    setStatus('loading');
    setMessage('VPN bağlantısı kesiliyor...');
    setMessageType('');

    try {
      const response = await fetch('/api/disconnect', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const data = await response.json();
      
      if (data.success) {
        setStatus('disconnected');
        setMessage(data.message);
        setMessageType('success');
      } else {
        setStatus('connected');
        setMessage(data.message);
        setMessageType('error');
      }
    } catch (error) {
      setStatus('connected');
      setMessage('Bağlantı kesme hatası: ' + error.message);
      setMessageType('error');
    }
  };

  const getStatusText = () => {
    switch (status) {
      case 'connected':
        return 'VPN Bağlı';
      case 'disconnected':
        return 'VPN Bağlı Değil';
      case 'loading':
        return 'İşlem Yapılıyor...';
      default:
        return 'Bilinmeyen Durum';
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>VPN Yönetim Paneli</h1>
        <div className={`status ${status}`}>
          {getStatusText()}
        </div>
      </header>

      <div className="buttons">
        <button
          className="btn btn-connect"
          onClick={handleConnect}
          disabled={status === 'loading' || status === 'connected'}
        >
          Bağlan
        </button>
        <button
          className="btn btn-disconnect"
          onClick={handleDisconnect}
          disabled={status === 'loading' || status === 'disconnected'}
        >
          Bağlantıyı Kes
        </button>
      </div>

      {message && (
        <div className={`message ${messageType}`}>
          {message}
        </div>
      )}
    </div>
  );
}

export default App;