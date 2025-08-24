"""
Hyperloop Güvenli İletişim Sistemi - İstemci Uygulaması

Bu modül, Hyperloop sisteminin güvenli iletişim istemcisini gerçekleştirir.
mTLS (mutual TLS) kullanarak sunucuya bağlanır ve telemetri verilerini
güvenli şekilde iletir.

İstemci Özellikleri:
- mTLS ile sunucu kimlik doğrulama
- Otomatik telemetri üretimi
- Gerçek zamanlı veri iletimi
- Güvenli mesaj şifreleme
- Graceful shutdown desteği
- Hata toleransı ve yeniden bağlanma

Veri İletim Özellikleri:
- 200ms aralıklarla telemetri üretimi
- LZ4 sıkıştırma ile verimlilik
- CRC32 ile veri bütünlüğü
- Protokol header'ları ile çerçeveleme
- AAD (Associated Authenticated Data) desteği

Güvenlik Özellikleri:
- Sertifika tabanlı kimlik doğrulama
- ChaCha20-Poly1305 şifreleme
- Otomatik anahtar rotasyonu
- Güvenli bağlantı yönetimi
- Hostname doğrulama (demo'da devre dışı)
"""

import socket
import ssl
import time
import signal
import sys
import os
from typing import Optional, Dict

# Proje modüllerini import et
from crypto_layer import SessionCrypto
from telemetry import generate
from protocol import pack_message, unpack_message

# Sunucu bağlantı bilgileri
HOST, PORT = "127.0.0.1", 9443

# Graceful shutdown için global bayrak
shutdown_flag = False


def signal_handler(signum, frame):
    """
    Shutdown sinyallerini yakalar ve graceful shutdown başlatır.

    Bu fonksiyon:
    1. SIGINT (Ctrl+C) ve SIGTERM sinyallerini yakalar
    2. Global shutdown bayrağını set eder
    3. İstemcinin güvenli şekilde kapanmasını sağlar

    Args:
        signum: Gelen sinyal numarası
        frame: Stack frame bilgisi
    """
    global shutdown_flag
    print(f"\nReceived signal {signum}, shutting down gracefully...")
    shutdown_flag = True


def main() -> None:
    """
    Ana istemci fonksiyonu.

    Bu fonksiyon:
    1. SSL/TLS context'i oluşturur
    2. Sertifika dosyalarını yükler
    3. Sunucuya bağlanır
    4. Telemetri verilerini üretir ve iletir
    5. Graceful shutdown yönetir

    Bağlantı Akışı:
    1. TCP bağlantısı kur
    2. SSL/TLS handshake yap
    3. Sertifika doğrulama
    4. SessionCrypto başlat
    5. Telemetri döngüsü

    Veri İletim Döngüsü:
    1. Telemetri verisi üret
    2. Protokol formatında paketle
    3. Şifrele
    4. Mesaj uzunluğu + veri gönder
    5. 200ms bekle

    Sertifika Gereksinimleri:
    - client.crt: İstemci sertifikası
    - client.key: İstemci özel anahtarı
    - ca.crt: CA sertifikası (sunucu doğrulama için)

    Güvenlik Ayarları:
    - verify_mode = CERT_REQUIRED (mTLS)
    - Purpose.SERVER_AUTH (sunucu kimlik doğrulama)
    - Hostname doğrulama (demo'da devre dışı)
    """
    global shutdown_flag

    # Signal handler'ları kur (graceful shutdown için)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # 1. SSL context oluştur
        ctx = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cafile="certs/out/ca.crt"
        )

        # 2. İstemci sertifikalarını yükle
        ctx.load_cert_chain("certs/out/client.crt", "certs/out/client.key")

        # Demo amaçlı hostname doğrulamasını devre dışı bırak
        # Üretimde bu ayar güvenlik için gerekli
        ctx.check_hostname = False

        # 3. TCP bağlantısı kur
        with socket.create_connection((HOST, PORT), timeout=10) as sock:
            # 4. SSL/TLS wrapper ile bağlantıyı sar
            with ctx.wrap_socket(sock, server_hostname="server.local") as ssock:
                # 5. Bağlantı bilgilerini göster
                print("TLS bağlandı. Peer:", ssock.getpeercert())

                # 6. SessionCrypto başlat
                # Gerçek sistemde: TLS master secret'tan türetilir
                # Demo amaçlı: Sabit değer kullanılıyor
                shared = b"demo_shared_secret_from_tls"
                crypto = SessionCrypto(shared)

                # 7. Önceki telemetri verisi (değişim analizi için)
                prev = None

                print("Sending telemetry data... Press Ctrl+C to stop")

                # 8. Ana telemetri döngüsü
                while not shutdown_flag:
                    try:
                        # 8.1. Telemetri verisi üret
                        msg = generate(prev)

                        # 8.2. Önceki veriyi güncelle (bayrak mesajları hariç)
                        # Bayrak mesajları önceki veriyi değiştirmez
                        prev = msg if "flag" not in msg else prev

                        # 8.3. Protokol formatında paketle
                        # LZ4 sıkıştırma ile verimlilik artır
                        payload = pack_message(msg)

                        # 8.4. Şifrele
                        # AAD (Associated Authenticated Data) ile ek güvenlik
                        # "HLP1" magic number'ı AAD olarak kullan
                        blob = crypto.encrypt(payload, aad=b"HLP1")

                        # 8.5. Mesajı gönder
                        # Format: [4 byte length][encrypted data]
                        message_data = len(blob).to_bytes(4, "big") + blob
                        ssock.sendall(message_data)

                        # 8.6. Bir sonraki örnek için bekle
                        # 200ms = 5 Hz örnekleme hızı
                        time.sleep(0.2)

                    except KeyboardInterrupt:
                        # Ctrl+C ile graceful shutdown
                        break
                    except Exception as e:
                        # Mesaj gönderme hatası
                        print(f"Error sending message: {e}")
                        break

    except FileNotFoundError as e:
        # Sertifika dosyaları bulunamadı
        print(f"Certificate files not found: {e}")
        print("Please run 'python certs/make_test_certs.py' first")
        sys.exit(1)
    except socket.timeout:
        # Bağlantı timeout - sunucu çalışmıyor olabilir
        print("Connection timeout - server may not be running")
        sys.exit(1)
    except ConnectionRefusedError:
        # Bağlantı reddedildi - sunucu çalışmıyor olabilir
        print("Connection refused - server may not be running")
        sys.exit(1)
    except Exception as e:
        # Genel istemci hatası
        print(f"Client error: {e}")
        sys.exit(1)
    finally:
        # İstemci kapanış mesajı
        print("Client shutdown complete")


if __name__ == "__main__":
    main()
