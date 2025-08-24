"""
Hyperloop Güvenli İletişim Sistemi - Telemetri Üretimi ve Simülasyonu

Bu modül, Hyperloop sisteminin telemetri verilerini simüle eder ve üretir.
Gerçek sistemde bu veriler sensörlerden gelir, ancak demo amaçlı olarak
yapay veri üretimi yapılır.

Telemetri Veri Türleri:
1. Düzenli Telemetri:
   - speed: Hız (km/h)
   - pressure: Basınç (bar)
   - temperature: Sıcaklık (°C)
   - voltage: Voltaj (V)
   - ts: Timestamp (Unix time)

2. Bayrak Mesajları:
   - BRAKE_CMD: Fren komutu
   - EMERGENCY_STOP: Acil dur
   - SYSTEM_CHECK: Sistem kontrolü
   - MAINTENANCE_ALERT: Bakım uyarısı
   - PERFORMANCE_WARNING: Performans uyarısı

Veri Üretim Özellikleri:
- Gerçekçi gürültü ekleme (jitter)
- Fiziksel sınırlar içinde değerler
- Zaman bazlı veri üretimi
- Rastgele bayrak mesajları
- Hata toleransı ve fallback

Kullanım Alanları:
- Sistem testi ve geliştirme
- Performans analizi
- Protokol doğrulama
- Eğitim ve demo
"""

import random
import time
from typing import Dict, Optional, Union

# Varsayılan telemetri değerleri - gerçekçi başlangıç değerleri
DEFAULT_TELEMETRY = {
    "speed": 120.0,  # km/h - tipik Hyperloop hızı
    "pressure": 0.95,  # bar - atmosfer basıncı altında
    "temperature": 24.0,  # °C - oda sıcaklığı
    "voltage": 48.0,  # V - sistem voltajı
}

# Geçerli bayrak türleri - sistem durumlarını temsil eder
VALID_FLAGS = [
    "BRAKE_CMD",  # Fren komutu - normal operasyon
    "EMERGENCY_STOP",  # Acil dur - güvenlik
    "SYSTEM_CHECK",  # Sistem kontrolü - bakım
    "MAINTENANCE_ALERT",  # Bakım uyarısı - planlı
    "PERFORMANCE_WARNING",  # Performans uyarısı - izleme
]


def generate_telemetry(prev: Optional[Dict] = None, count: Optional[int] = None, flag: Optional[str] = None) -> Dict:
    """
    Telemetri verisi üretir ve gerçekçi değişimler ekler.

    Args:
        prev: Önceki telemetri verisi (None olabilir)
        count: Örnek sayısı (None olabilir)
        flag: Özel bayrak mesajı (None olabilir)

    Returns:
        Yeni telemetri verisi sözlüğü

    Raises:
        ValueError: Girdi doğrulama hatası
    """
    # Girdi doğrulama
    if prev is not None and not isinstance(prev, dict):
        raise ValueError("prev must be a dictionary or None")
    
    if count is not None:
        if not isinstance(count, int) or count < 0:
            raise ValueError("count must be a non-negative integer")
        # Count parametresi için özel telemetri üret
        return {
            **DEFAULT_TELEMETRY.copy(),
            "count": count,
            "ts": time.time(),
        }
    
    if flag is not None:
        if flag not in VALID_FLAGS:
            raise ValueError("Invalid flag")
        # Bayrak mesajı üret
        return {
            "flag": flag,
            "ts": time.time(),
            "severity": random.choice(["LOW", "MEDIUM", "HIGH"]),
            "source": "telemetry_system",
        }
    
    # Normal telemetri üretimi
    return generate(prev)


def jitter(base: Union[int, float], jitter_factor: float = 0.05) -> float:
    """
    Değere kontrollü gürültü ekler.

    Args:
        base: Orijinal değer
        jitter_factor: Gürültü faktörü (0.0 ile 1.0 arası)

    Returns:
        Gürültü eklenmiş değer

    Raises:
        ValueError: Geçersiz girdi
    """
    if not isinstance(base, (int, float)):
        raise ValueError("base must be a number")
    
    if not isinstance(jitter_factor, (int, float)) or jitter_factor < 0:
        raise ValueError("jitter_factor must be a non-negative number")
    
    if jitter_factor == 0:
        return float(base)
    
    # Rastgele değişim üret
    change = random.uniform(-jitter_factor, jitter_factor)
    result = base * (1 + change)
    
    return result


def generate(prev: Optional[Dict] = None) -> Dict:
    """
    Telemetri verisi üretir ve gerçekçi değişimler ekler.

    Args:
        prev: Önceki telemetri verisi (None olabilir)

    Returns:
        Yeni telemetri verisi sözlüğü

    Raises:
        ValueError: Girdi doğrulama hatası
    """
    # Girdi doğrulama
    if prev is not None and not isinstance(prev, dict):
        raise ValueError("prev must be a dictionary or None")

    try:
        # 1. Önceki veri yoksa varsayılan değerleri kullan
        if prev is None:
            prev = DEFAULT_TELEMETRY.copy()

        # 2. Veri yapısını doğrula ve eksik alanları tamamla
        for key in DEFAULT_TELEMETRY:
            if key not in prev:
                prev[key] = DEFAULT_TELEMETRY[key]

        # 3. Gürültü ekleme fonksiyonu (jitter)
        def jitter_with_bounds(value: float, field: str) -> float:
            """
            Değere kontrollü gürültü ekler ve sınırları korur.
            """
            # Değer tipini kontrol et
            if not isinstance(value, (int, float)):
                return DEFAULT_TELEMETRY.get(field, 120.0)

            # Rastgele değişim üret (-0.1 ile +0.1 arası)
            change = random.uniform(-0.1, 0.1)
            result = value + change

            # Fiziksel sınırları uygula
            if field == "speed":
                result = max(0, min(200, result))  # 0-200 km/h
            elif field == "pressure":
                result = max(0.8, min(1.2, result))  # 0.8-1.2 bar
            elif field == "temperature":
                result = max(15, min(35, result))  # 15-35 °C
            elif field == "voltage":
                result = max(40, min(60, result))  # 40-60 V

            return result

        # 4. Yeni örnek üret - her alan için jitter ekle
        sample = {}
        for key, value in prev.items():
            if key != "ts":  # Timestamp'i önceki veriden alma
                sample[key] = jitter_with_bounds(value, key)

        # 5. Timestamp ekle (Unix time)
        sample["ts"] = time.time()

        # 6. Rastgele bayrak mesajları üret (%5 olasılık)
        if random.random() < 0.05:
            # Bayrak türünü rastgele seç
            flag_type = random.choice(VALID_FLAGS)

            # Bayrak mesajı oluştur - orijinal veriyi koru
            sample = {
                **sample,  # Orijinal telemetri verisini koru
                "flag": flag_type,
                "severity": random.choice(["LOW", "MEDIUM", "HIGH"]),
                "source": "telemetry_system",
            }

        return sample

    except Exception as e:
        # Hata durumunda güvenli fallback
        print(f"Warning: Telemetry generation failed, using defaults: {e}")
        return {
            **DEFAULT_TELEMETRY.copy(),
            "ts": time.time(),
            "error": "generation_failed",
        }


def generate_batch(size: int) -> list:
    """
    Birden fazla telemetri örneği üretir.

    Args:
        size: Üretilecek örnek sayısı

    Returns:
        Telemetri örnekleri listesi

    Raises:
        ValueError: Size geçersizse
    """
    if not isinstance(size, int) or size <= 0:
        raise ValueError("size must be a positive integer")
    
    samples = []
    prev = None
    
    for i in range(size):
        sample = generate_telemetry(prev)
        samples.append(sample)
        prev = sample
    
    return samples


def validate_telemetry(data: Dict) -> bool:
    """
    Telemetri verisinin geçerliliğini kontrol eder.
    Args:
        data: Kontrol edilecek telemetri verisi
    Returns:
        Veri geçerliyse True, değilse False
    """
    # 1. Veri tipi kontrolü
    if not isinstance(data, dict):
        return False
    # 2. Timestamp kontrolü
    if "ts" not in data:
        return False
    # Timestamp değerini doğrula
    try:
        ts = data["ts"]
        if not isinstance(ts, (int, float)) or ts < 0:
            return False
    except:
        return False
    # 3. Bayrak mesajı kontrolü
    if "flag" in data:
        if data["flag"] not in VALID_FLAGS:
            return False
        return True  # Bayrak mesajları için sadece timestamp yeterli
    # 4. Düzenli telemetri kontrolü
    required_fields = ["speed", "pressure", "temperature", "voltage"]
    for field in required_fields:
        if field not in data:
            return False
        # Alan değerini kontrol et
        value = data[field]
        if not isinstance(value, (int, float)):
            return False 
        # Değer aralıklarını kontrol et
        if field == "speed" and (value < 0 or value > 200):
            return False
        elif field == "pressure" and (value < 0.8 or value > 1.2):
            return False
        elif field == "temperature" and (value < 15 or value > 35):
            return False
        elif field == "voltage" and (value < 40 or value > 60):
            return False

    return True


def get_telemetry_stats(batch: list) -> Dict:
    """
    Telemetri örneklerinden istatistik hesaplar.

    Args:
        batch: Analiz edilecek telemetri örnekleri listesi

    Returns:
        İstatistik bilgileri sözlüğü

    Raises:
        ValueError: Batch geçersizse
    """
    if not isinstance(batch, list):
        raise ValueError("batch must be a list")
    
    # Boş liste kontrolü
    if not batch:
        return {
            "count": 0,
            "flag_count": 0,
            "regular_count": 0,
            "speed_stats": {"min": None, "max": None, "avg": None},
            "pressure_stats": {"min": None, "max": None, "avg": None},
            "temperature_stats": {"min": None, "max": None, "avg": None},
            "voltage_stats": {"min": None, "max": None, "avg": None},
        }

    try:
        # 1. Temel istatistikler
        stats = {
            "count": len(batch),
            "flag_count": sum(1 for s in batch if "flag" in s),
            "regular_count": sum(1 for s in batch if "flag" not in s),
        }

        # 2. Düzenli telemetri için alan istatistikleri
        regular_samples = [s for s in batch if "flag" not in s]
        
        # Tüm alanlar için istatistikleri başlat
        for field in ["speed", "pressure", "temperature", "voltage"]:
            stats[f"{field}_stats"] = {"min": None, "max": None, "avg": None, "count": 0}
        
        if regular_samples:
            for field in ["speed", "pressure", "temperature", "voltage"]:
                # Her alan için değerleri topla
                values = [s.get(field) for s in regular_samples if field in s and s.get(field) is not None]
                if values:
                    # İstatistikleri hesapla
                    stats[f"{field}_stats"] = {
                        "min": min(values),
                        "max": max(values),
                        "avg": sum(values) / len(values),
                        "count": len(values),
                    }

        return stats

    except Exception as e:
        # Hata durumunda hata bilgisi döner
        return {"error": str(e)}
