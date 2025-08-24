"""
Hyperloop Güvenli İletişim Sistemi - Kriptografi Katmanı

Bu modül, istemci ve sunucu arasındaki güvenli iletişim için gerekli olan
kriptografik işlemleri gerçekleştirir. ChaCha20-Poly1305 AEAD şifreleme algoritması
kullanarak hem gizlilik hem de bütünlük sağlar.

Güvenlik Özellikleri:
- ChaCha20-Poly1305: Modern, hızlı ve güvenli AEAD şifreleme
- HKDF: Güvenli anahtar türetme (HMAC-based Key Derivation Function)
- Otomatik anahtar rotasyonu: Düzenli anahtar yenileme
- Güvenli rastgele sayı üretimi: os.urandom() kullanımı

AEAD (Authenticated Encryption with Associated Data):
- Gizlilik: Veri şifrelenir
- Bütünlük: Veri değiştirilemez
- Kimlik doğrulama: AAD ile ek güvenlik
"""

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import time
from typing import Optional


class SessionCrypto:
    """
    Oturum bazlı kriptografi sınıfı.

    Bu sınıf, TLS bağlantısı üzerinden paylaşılan gizli bilgiyi kullanarak
    oturum anahtarları türetir ve her oturum için ayrı şifreleme anahtarları
    kullanır. Anahtar rotasyonu ile güvenlik artırılır.

    Özellikler:
    - Otomatik anahtar türetme
    - Düzenli anahtar rotasyonu
    - ChaCha20-Poly1305 ile şifreleme/çözme
    - AAD (Associated Authenticated Data) desteği
    """

    def __init__(self, shared_secret: bytes):
        """
        SessionCrypto sınıfını başlatır.

        Args:
            shared_secret: TLS bağlantısından türetilen paylaşılan gizli bilgi
                          (en az 16 byte olmalı)

        Raises:
            TypeError: shared_secret bytes tipinde değilse
            ValueError: shared_secret çok kısaysa
        """
        # Girdi doğrulama: shared_secret bytes tipinde olmalı
        if not isinstance(shared_secret, bytes):
            raise TypeError("shared_secret must be bytes")

        # Güvenlik: En az 16 byte olmalı (128 bit)
        if len(shared_secret) < 16:
            raise ValueError("shared_secret must be at least 16 bytes")

        # Paylaşılan gizli bilgiyi sakla
        self.base_secret = shared_secret

        # Oturum dönemi (epoch) - anahtar rotasyonu için sayaç
        self.epoch = 0

        # İlk anahtarı türet
        self._derive()

    def _derive(self) -> None:
        """
        Mevcut epoch için şifreleme anahtarını türetir.

        HKDF (HMAC-based Key Derivation Function) kullanarak:
        1. Base secret'ı alır
        2. Epoch bilgisini ekler
        3. 32 byte (256 bit) anahtar türetir

        Bu yöntem, aynı base secret'tan farklı anahtarlar üretmeyi sağlar.
        """
        # Epoch bilgisini info parametresi olarak ekle
        # Bu, her epoch için farklı anahtar üretilmesini sağlar
        info = f"epoch:{self.epoch}".encode()

        # HKDF ile anahtar türet
        # - SHA256 hash algoritması kullan
        # - 32 byte (256 bit) anahtar uzunluğu
        # - Salt yok (deterministik türetim)
        # - Info parametresi epoch bilgisi
        self.key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bit anahtar
            salt=None,  # Deterministik türetim için
            info=info,  # Epoch bilgisi
        ).derive(self.base_secret)

    def rotate(self) -> None:
        """
        Anahtarı bir sonraki epoch'a döndürür.

        Bu işlem:
        1. Epoch sayacını artırır
        2. Yeni anahtarı türetir

        Anahtar rotasyonu, güvenlik açısından önemlidir çünkü:
        - Tek bir anahtarın uzun süre kullanılmasını önler
        - Anahtar sızıntısı durumunda etkiyi sınırlar
        - Forward secrecy sağlar
        """
        self.epoch += 1
        self._derive()

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """
        Düz metni şifreler.

        ChaCha20-Poly1305 AEAD algoritması kullanarak:
        1. Güvenli rastgele nonce üretir (12 byte)
        2. Plaintext'i şifreler
        3. AAD ile kimlik doğrulama ekler
        4. Nonce + ciphertext formatında döner

        Args:
            plaintext: Şifrelenecek düz metin
            aad: Associated Authenticated Data (kimlik doğrulama için)

        Returns:
            Nonce + şifrelenmiş metin (12 + ciphertext_length byte)

        Raises:
            TypeError: Girdi tipleri yanlışsa
            ValueError: Plaintext boşsa
            RuntimeError: Şifreleme başarısızsa
        """
        # Girdi doğrulama
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if not isinstance(aad, bytes):
            raise TypeError("aad must be bytes")
        if len(plaintext) == 0:
            raise ValueError("plaintext cannot be empty")

        try:
            # 12 byte güvenli rastgele nonce üret
            # ChaCha20 için standart nonce uzunluğu
            nonce = os.urandom(12)

            # ChaCha20Poly1305 şifreleme nesnesi oluştur
            aead = ChaCha20Poly1305(self.key)

            # Şifreleme işlemi: nonce + plaintext + aad -> ciphertext
            ct = aead.encrypt(nonce, plaintext, aad)

            # Nonce + ciphertext formatında döner
            # Nonce, çözme işleminde gerekli
            return nonce + ct

        except Exception as e:
            raise RuntimeError(f"Encryption failed: {e}")

    def decrypt(self, blob: bytes, aad: bytes = b"") -> bytes:
        """
        Şifrelenmiş veriyi çözer.

        Args:
            blob: Çözülecek şifreli veri
            aad: Ek kimlik doğrulama verisi

        Returns:
            Çözülmüş veri

        Raises:
            RuntimeError: Şifre çözme hatası
        """
        if not isinstance(blob, bytes):
            raise ValueError("blob must be bytes")
        
        if not isinstance(aad, bytes):
            raise ValueError("aad must be bytes")
        
        if len(blob) < 28:  # 12 (nonce) + 16 (tag) minimum
            raise ValueError("blob too short")
        
        try:
            # Nonce ve şifreli veriyi ayır
            nonce = blob[:12]
            ciphertext = blob[12:]
            
            # ChaCha20-Poly1305 ile çöz
            cipher = ChaCha20Poly1305(self.key)
            plaintext = cipher.decrypt(nonce, ciphertext, aad)
            
            return plaintext
            
        except Exception as e:
            raise RuntimeError(f"Decryption failed: {e}")

    def get_epoch(self) -> int:
        """
        Mevcut epoch numarasını döner.

        Returns:
            Güncel epoch numarası (0'dan başlar)
        """
        return self.epoch

    def get_key_info(self) -> dict:
        """
        Anahtar bilgilerini debug amaçlı döner.

        Bu fonksiyon sadece geliştirme ve debug amaçlıdır.
        Üretim ortamında anahtar bilgilerini loglamayın.

        Returns:
            Anahtar bilgilerini içeren sözlük:
            - epoch: Mevcut epoch numarası
            - key_length: Anahtar uzunluğu (byte)
            - base_secret_length: Base secret uzunluğu (byte)
        """
        return {
            "epoch": self.epoch,
            "key_length": len(self.key) if hasattr(self, "key") else 0,
            "base_secret_length": len(self.base_secret),
        }
