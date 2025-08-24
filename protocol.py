"""
Hyperloop Güvenli İletişim Sistemi - Protokol Katmanı

Bu modül, istemci ve sunucu arasındaki mesajlaşma protokolünü tanımlar.
Mesajların paketlenmesi, sıkıştırılması, CRC hesaplanması ve çözülmesi
işlemlerini gerçekleştirir.

Protokol Özellikleri:
- Sabit magic number ile mesaj tanımlama
- LZ4 ile hızlı veri sıkıştırma
- CRC32 ile veri bütünlüğü kontrolü
- Esnek mesaj bayrakları sistemi
- Maksimum mesaj boyutu sınırlaması

Mesaj Formatı:
[MAGIC:4][FLAGS:1][CRC32:4][DATA_LEN:4][DATA:variable]

Güvenlik:
- Magic number ile mesaj doğrulama
- CRC32 ile veri bütünlüğü
- Mesaj boyutu sınırlaması
- Hata durumunda güvenli davranış
"""

import json
import struct
import zlib
from typing import Dict, Any, Tuple, Optional
import lz4.frame as lz4

# Protokol sabitleri
MAGIC = b"HLP1"  # HyperLoop Proto v1 - 4 byte magic number
MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB maksimum mesaj boyutu


class ProtocolError(Exception):
    """
    Protokol hataları için özel istisna sınıfı.

    Bu sınıf, protokol işlemleri sırasında oluşan hataları
    yakalamak ve işlemek için kullanılır.
    """

    pass


def pack_message(payload: Dict[str, Any], compress: bool = True) -> bytes:
    """
    Mesajı protokol formatında paketler.

    Bu fonksiyon:
    1. JSON payload'ı UTF-8 bytes'a çevirir
    2. Gerekirse LZ4 ile sıkıştırır
    3. CRC32 hesaplar
    4. Protokol header'ını oluşturur
    5. Tüm bileşenleri birleştirir

    Args:
        payload: Paketlenecek veri (JSON serializable dict)
        compress: Sıkıştırma kullanılıp kullanılmayacağı

    Returns:
        Protokol formatında paketlenmiş mesaj

    Raises:
        TypeError: Payload dict değilse veya compress bool değilse
        ValueError: Mesaj çok büyükse
        ProtocolError: Paketleme başarısızsa

    Mesaj Yapısı:
    [MAGIC:4][FLAGS:1][CRC32:4][DATA_LEN:4][DATA:variable]
    """
    # Girdi doğrulama
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dictionary")
    if not isinstance(compress, bool):
        raise TypeError("compress must be a boolean")

    try:
        # 1. JSON payload'ı UTF-8 bytes'a çevir
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        # 2. Mesaj boyutu kontrolü (güvenlik)
        if len(data) > MAX_MESSAGE_SIZE:
            raise ValueError(
                f"Message too large: {len(data)} bytes (max: {MAX_MESSAGE_SIZE})"
            )

        # 3. Bayrakları hazırla
        flags = 0

        # 4. Sıkıştırma kararı (sadece veri yeterince büyükse)
        if compress and len(data) > 100:  # 100 byte'dan büyükse sıkıştır
            try:
                compressed_data = lz4.compress(data)
                # Sıkıştırma gerçekten boyutu azaltıyorsa kullan
                if len(compressed_data) < len(data):
                    data = compressed_data
                    flags |= 0x01  # Sıkıştırma bayrağını set et
            except Exception as e:
                # Sıkıştırma başarısızsa uyarı ver ve devam et
                print(f"Warning: Compression failed, continuing without: {e}")

        # 5. CRC32 hesapla (veri bütünlüğü için)
        # zlib.crc32 32-bit integer döner, 32-bit'e maskele
        crc = zlib.crc32(data) & 0xFFFFFFFF

        # 6. Protokol header'ını oluştur
        # Format: magic(4) + flags(1) + crc(4) + data_len(4)
        header = MAGIC + struct.pack("!BI", flags, crc) + struct.pack("!I", len(data))

        # 7. Header + data'yı birleştir ve döner
        return header + data

    except Exception as e:
        raise ProtocolError(f"Failed to pack message: {e}")


def unpack_message(buf: bytes) -> Dict[str, Any]:
    """
    Protokol formatındaki mesajı çözer ve doğrular.

    Bu fonksiyon:
    1. Magic number'ı doğrular
    2. Header'ı parse eder
    3. CRC32 ile veri bütünlüğünü kontrol eder
    4. Gerekirse sıkıştırmayı çözer
    5. JSON'ı parse eder

    Args:
        buf: Çözülecek protokol mesajı

    Returns:
        Çözülmüş JSON payload

    Raises:
        TypeError: Buffer bytes değilse
        ProtocolError: Protokol hatası varsa
        ValueError: CRC uyuşmazsa
        json.JSONDecodeError: JSON geçersizse
        UnicodeDecodeError: UTF-8 geçersizse

    Güvenlik Kontrolleri:
    - Magic number doğrulama
    - Header boyutu kontrolü
    - Mesaj boyutu sınırlaması
    - CRC32 bütünlük kontrolü
    """
    # Girdi doğrulama
    if not isinstance(buf, bytes):
        raise TypeError("buf must be bytes")

    # Minimum header boyutu kontrolü: magic(4) + flags(1) + crc(4) + len(4) = 13
    if len(buf) < len(MAGIC) + 9:
        raise ProtocolError("Buffer too short for valid message")

    try:
        # 1. Magic number doğrulama
        if not buf.startswith(MAGIC):
            raise ProtocolError(
                f"Invalid magic number: expected {MAGIC}, got {buf[:len(MAGIC)]}"
            )

        # 2. Header parsing - offset tracking
        off = len(MAGIC)  # Magic'ten sonra başla

        # Flags byte'ını oku
        if off + 1 > len(buf):
            raise ProtocolError("Buffer too short for flags")
        (flags,) = struct.unpack_from("!B", buf, off)
        off += 1

        # CRC32'yi oku
        if off + 4 > len(buf):
            raise ProtocolError("Buffer too short for CRC")
        (crc_expected,) = struct.unpack_from("!I", buf, off)
        off += 4

        # Data length'i oku
        if off + 4 > len(buf):
            raise ProtocolError("Buffer too short for data length")
        (data_len,) = struct.unpack_from("!I", buf, off)
        off += 4

        # 3. Mesaj boyutu doğrulama (güvenlik)
        if data_len < 0 or data_len > MAX_MESSAGE_SIZE:
            raise ProtocolError(f"Invalid data length: {data_len}")

        # Buffer'da yeterli data var mı kontrol et
        if off + data_len > len(buf):
            raise ProtocolError(
                f"Buffer too short for data: expected {data_len}, got {len(buf) - off}"
            )

        # 4. Data'yı çıkar
        data = buf[off : off + data_len]

        # 5. CRC32 bütünlük kontrolü
        crc_calc = zlib.crc32(data) & 0xFFFFFFFF
        if crc_calc != crc_expected:
            raise ProtocolError(
                f"CRC mismatch: expected {crc_expected:08x}, got {crc_calc:08x}"
            )

        # 6. Sıkıştırma çözme (bayrak set edilmişse)
        if flags & 0x01:
            try:
                data = lz4.decompress(data)
            except Exception as e:
                raise ProtocolError(f"Decompression failed: {e}")

        # 7. JSON parse etme
        try:
            return json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise ProtocolError(f"Invalid JSON: {e}")
        except UnicodeDecodeError as e:
            raise ProtocolError(f"Invalid UTF-8: {e}")

    except ProtocolError:
        # ProtocolError'ları olduğu gibi yükselt
        raise
    except Exception as e:
        # Beklenmeyen hataları ProtocolError olarak sarmala
        raise ProtocolError(f"Unexpected error unpacking message: {e}")


def validate_message_structure(msg: Dict[str, Any]) -> bool:
    """
    Mesaj yapısını doğrular.

    Bu fonksiyon, çözülmüş mesajın gerekli alanları
    içerip içermediğini kontrol eder.

    Gerekli Alanlar:
    - ts: Timestamp (sayısal, pozitif)

    Args:
        msg: Doğrulanacak mesaj sözlüğü

    Returns:
        True: Mesaj geçerliyse, False: Geçersizse
    """
    # Mesaj dict tipinde olmalı
    if not isinstance(msg, dict):
        return False

    # Timestamp alanı gerekli
    if "ts" not in msg:
        return False

    # Timestamp doğrulama
    try:
        ts = msg["ts"]
        if not isinstance(ts, (int, float)):
            return False
        if ts < 0:
            return False
    except:
        return False

    return True


def get_message_info(buf: bytes) -> Dict[str, Any]:
    """
    Mesaj hakkında bilgi verir (tam çözme yapmadan).

    Bu fonksiyon, mesajı tamamen çözmeden header
    bilgilerini çıkarır. Debug ve analiz amaçlıdır.

    Args:
        buf: Analiz edilecek mesaj buffer'ı

    Returns:
        Mesaj bilgilerini içeren sözlük:
        - magic: Magic number string'i
        - flags: Bayrak değeri
        - compressed: Sıkıştırılmış mı?
        - crc: CRC32 değeri (hex)
        - data_length: Data uzunluğu
        - total_length: Toplam mesaj uzunluğu
        - header_length: Header uzunluğu
        - error: Hata varsa hata mesajı
    """
    # Buffer çok kısaysa hata döner
    if len(buf) < len(MAGIC) + 9:
        return {"error": "Buffer too short"}

    try:
        # Magic number kontrolü
        if not buf.startswith(MAGIC):
            return {"error": "Invalid magic"}

        # Header parsing
        off = len(MAGIC)
        (flags,) = struct.unpack_from("!B", buf, off)
        off += 1
        (crc,) = struct.unpack_from("!I", buf, off)
        off += 4
        (data_len,) = struct.unpack_from("!I", buf, off)

        # Bilgi sözlüğünü oluştur
        return {
            "magic": MAGIC.decode(),
            "flags": flags,
            "compressed": bool(flags & 0x01),
            "crc": f"{crc:08x}",
            "data_length": data_len,
            "total_length": len(buf),
            "header_length": off + 4,
        }
    except Exception as e:
        return {"error": str(e)}
