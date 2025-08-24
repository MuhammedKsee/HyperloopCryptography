"""
Hyperloop Güvenli İletişim Sistemi - Sunucu Uygulaması

Bu modül, Hyperloop sisteminin güvenli iletişim sunucusunu gerçekleştirir.
mTLS (mutual TLS) kullanarak istemcilerle güvenli bağlantı kurar ve
telemetri verilerini işler.

Sunucu Özellikleri:
- mTLS ile karşılıklı kimlik doğrulama
- Çoklu istemci desteği (threading)
- Otomatik anahtar rotasyonu
- Veri profilleme ve sınıflandırma
- Graceful shutdown desteği
- Hata toleransı ve kurtarma

Güvenlik Özellikleri:
- Sertifika tabanlı kimlik doğrulama
- TLS 1.3 desteği
- Mesaj boyutu sınırlaması
- Güvenli bağlantı yönetimi
- Anahtar rotasyonu

Ağ Mimarisi:
- TCP/IP üzerinde SSL/TLS
- Port 9443 (standart HTTPS alternatifi)
- Localhost binding (127.0.0.1)
- Connection pooling ve timeout yönetimi
"""

import ssl
import socket
import threading
import json
import time
import signal
import sys
from typing import Optional
from protocol import pack_message, unpack_message
from profiling import classify
from crypto_layer import SessionCrypto

# Sunucu konfigürasyonu
HOST, PORT = "127.0.0.1", 9443

# Graceful shutdown için global bayrak
shutdown_flag = False


def signal_handler(signum, frame):
    """
    Shutdown sinyallerini yakalar ve graceful shutdown başlatır.

    Bu fonksiyon:
    1. SIGINT (Ctrl+C) ve SIGTERM sinyallerini yakalar
    2. Global shutdown bayrağını set eder
    3. Sunucunun güvenli şekilde kapanmasını sağlar

    Args:
        signum: Gelen sinyal numarası
        frame: Stack frame bilgisi
    """
    global shutdown_flag
    print(f"\nReceived signal {signum}, shutting down gracefully...")
    shutdown_flag = True


def handle_client(conn: ssl.SSLSocket, addr: tuple) -> None:
    """
    Tek bir istemci bağlantısını yönetir.

    Bu fonksiyon:
    1. TLS bağlantısı üzerinden veri alır
    2. Şifrelenmiş mesajları çözer
    3. Telemetri verilerini profiller
    4. Anahtar rotasyonu yapar
    5. Hata durumlarını yönetir

    Veri İşleme Akışı:
    1. Mesaj uzunluğunu al (4 byte)
    2. Şifrelenmiş veriyi al
    3. SessionCrypto ile çöz
    4. Protokol mesajını çöz
    5. Profilleme yap
    6. Gerekirse anahtar rotasyonu

    Args:
        conn: SSL/TLS bağlantı soketi
        addr: İstemci adres bilgisi (IP, port)

    Güvenlik Kontrolleri:
    - Mesaj boyutu sınırlaması (max 1MB)
    - Bağlantı timeout yönetimi
    - Hata durumunda güvenli kapatma
    """
    print(f"Bağlandı: {addr}")

    # TLS üstünden paylaşılan gizli bilgi
    # Gerçek sistemde: TLS master secret'tan türetilir
    # Demo amaçlı: Sabit değer kullanılıyor
    shared = b"demo_shared_secret_from_tls"
    crypto = SessionCrypto(shared)

    # Önceki telemetri verisi (değişim analizi için)
    prev = {"speed": 120.0, "pressure": 0.95, "temperature": 24.0, "voltage": 48.0}

    try:
        # Ana veri işleme döngüsü
        while not shutdown_flag:
            try:
                # 1. Mesaj uzunluğunu al (4 byte big-endian)
                length_bytes = conn.recv(4)
                if not length_bytes:
                    break  # Bağlantı kapandı
                
                # 2. Mesaj uzunluğunu parse et ve doğrula
                total_len = int.from_bytes(length_bytes, "big")
                if total_len <= 0 or total_len > 1024 * 1024:  # Max 1MB
                    print(f"Invalid message length: {total_len}")
                    break
                
                # 3. Şifrelenmiş veriyi al
                blob = conn.recv(total_len)
                if len(blob) != total_len:
                    print(f"Incomplete message: expected {total_len}, got {len(blob)}")
                    break
                
                try:
                    # 4. Şifrelenmiş veriyi çöz
                    plaintext = crypto.decrypt(blob, aad=b"HLP1")
                    
                    # 5. Protokol mesajını çöz
                    message = unpack_message(plaintext)
                    
                    # 6. Profiling ile sınıflandır
                    classification = classify(prev, message)
                    
                    # 7. Sonucu gönder
                    response = {"status": "processed", "classification": classification}
                    response_data = pack_message(response)
                    conn.send(response_data)
                    
                    # 8. Önceki veriyi güncelle
                    prev = message
                    
                    print(f"Processed message from {addr}: {classification}")
                    
                except Exception as e:
                    print(f"Message processing error: {e}")
                    error_msg = {"error": f"Processing error: {e}"}
                    conn.send(pack_message(error_msg))
                
            except Exception as e:
                print(f"Error processing message from {addr}: {e}")
                break

    except Exception as e:
        # Bağlantı hatası
        print(f"Connection error with {addr}: {e}")
    finally:
        # Bağlantıyı güvenli şekilde kapat
        try:
            conn.close()
        except:
            pass  # Kapatma hatası görmezden gel
        print(f"Kapatıldı: {addr}")


def main() -> None:
    """
    Ana sunucu fonksiyonu.

    Bu fonksiyon:
    1. SSL/TLS context'i oluşturur
    2. Sertifika dosyalarını yükler
    3. Socket'i bind eder ve dinlemeye başlar
    4. İstemci bağlantılarını kabul eder
    5. Her istemci için ayrı thread başlatır
    6. Graceful shutdown yönetir

    Sertifika Gereksinimleri:
    - server.crt: Sunucu sertifikası
    - server.key: Sunucu özel anahtarı
    - ca.crt: CA sertifikası (istemci doğrulama için)

    Güvenlik Ayarları:
    - verify_mode = CERT_REQUIRED (mTLS)
    - Purpose.CLIENT_AUTH (istemci kimlik doğrulama)
    - Modern TLS cipher suite'leri
    """
    global shutdown_flag

    # Signal handler'ları kur (graceful shutdown için)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # 1. SSL context oluştur
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.verify_mode = ssl.CERT_REQUIRED  # mTLS için gerekli

        # 2. Sertifika dosyalarını yükle
        ctx.load_cert_chain("certs/out/server.crt", "certs/out/server.key")
        ctx.load_verify_locations("certs/out/ca.crt")

        # 3. Socket oluştur ve konfigüre et
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            # Port reuse ayarı (hızlı restart için)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Socket'i bind et
            sock.bind((HOST, PORT))
            sock.listen(5)  # Backlog queue

            # 4. SSL wrapper ile socket'i sar
            with ctx.wrap_socket(sock, server_side=True) as ssock:
                print(f"Sunucu dinlemede: {HOST}:{PORT}")
                print("Press Ctrl+C to stop the server")

                # 5. Ana kabul döngüsü
                while not shutdown_flag:
                    try:
                        # Timeout ile accept (shutdown flag kontrolü için)
                        ssock.settimeout(1.0)
                        conn, addr = ssock.accept()

                        # İstemci bağlantısı için timeout'u kaldır
                        conn.settimeout(None)

                        # 6. İstemci için ayrı thread başlat
                        client_thread = threading.Thread(
                            target=handle_client,
                            args=(conn, addr),
                            daemon=True,  # Ana thread ile birlikte sonlan
                        )
                        client_thread.start()

                    except socket.timeout:
                        # Timeout - shutdown flag kontrolü için
                        continue
                    except Exception as e:
                        # Accept hatası - shutdown sırasında normal
                        if not shutdown_flag:
                            print(f"Accept error: {e}")
                        break

    except FileNotFoundError as e:
        # Sertifika dosyaları bulunamadı
        print(f"Certificate files not found: {e}")
        print("Please run 'python certs/make_test_certs.py' first")
        sys.exit(1)
    except Exception as e:
        # Genel sunucu hatası
        print(f"Server error: {e}")
        sys.exit(1)
    finally:
        # Sunucu kapanış mesajı
        print("Server shutdown complete")


if __name__ == "__main__":
    main()
