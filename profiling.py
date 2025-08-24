"""
Hyperloop Güvenli İletişim Sistemi - Veri Profilleme ve Sınıflandırma

Bu modül, telemetri verilerini analiz eder ve öncelik seviyelerine göre
sınıflandırır. Basit karar ağacı mantığı kullanarak veri değişimlerini
izler ve kritik durumları tespit eder.

Sınıflandırma Kategorileri:
- "critical": Kritik değişimler (%2'den fazla)
- "stable": Kararlı durumlar
- "flag_only": Özel bayrak mesajları

İzlenen Alanlar:
- speed: Hız değişimleri
- pressure: Basınç değişimleri  
- temperature: Sıcaklık değişimleri
- voltage: Voltaj (sabit kalır, kritik değil)

Karar Mantığı:
1. Bayrak mesajları öncelikli olarak "flag_only" olarak sınıflandırılır
2. Kritik alanlarda %2'den fazla değişim "critical" olarak işaretlenir
3. Diğer durumlar "stable" olarak sınıflandırılır

Kullanım Alanları:
- Gerçek zamanlı sistem izleme
- Alarm ve uyarı sistemleri
- Veri önceliklendirme
- Kaynak yönetimi
"""






from typing import Dict, Literal, Optional, Union

# Sınıflandırma kategorileri - Literal type ile tip güvenliği
ProfileClass = Literal["critical", "stable", "flag_only"]


def classify(prev: Optional[Dict], curr: Dict) -> ProfileClass:
    """
    Telemetri verilerini önceki değerlere göre sınıflandırır.

    Args:
        prev: Önceki telemetri verisi (None olabilir)
        curr: Mevcut telemetri verisi

    Returns:
        Sınıflandırma sonucu (ProfileClass)

    Raises:
        ValueError: Girdi doğrulama hatası
    """
    # Girdi doğrulama - önce None kontrolü
    if curr is None:
        raise ValueError("curr cannot be None")
    
    if not isinstance(curr, dict):
        raise ValueError("curr must be a dictionary")
    
    if prev is not None and not isinstance(prev, dict):
        raise ValueError("prev must be a dictionary or None")

    # 1. Bayrak mesajı kontrolü (en yüksek öncelik)
    if "flag" in curr:
        return "flag_only"

    # 2. Önceki veri yoksa stable olarak sınıflandır
    if prev is None:
        return "stable"

    # 3. Kritik alanlardaki değişimleri kontrol et
    critical_fields = ["speed", "pressure", "temperature"]
    threshold = 0.02  # %2 değişim eşiği

    for field in critical_fields:
        if field in prev and field in curr:
            prev_val = prev[field]
            curr_val = curr[field]
            
            # Sayısal değer kontrolü
            if not isinstance(prev_val, (int, float)) or not isinstance(curr_val, (int, float)):
                continue
            
            # Sıfır değer kontrolü - sıfırdan küçük değişimler stable
            if prev_val == 0:
                if curr_val > 0.1:  # Sadece büyük değişimler kritik
                    return "critical"
                continue
            
            # Değişim yüzdesini hesapla
            change_percent = abs(curr_val - prev_val) / abs(prev_val)
            
            if change_percent >= threshold:
                return "critical"

    # 4. Hiçbir kritik değişim yoksa stable
    return "stable"


def get_classification_info(
    prev: Optional[Dict], curr: Dict
) -> Dict[str, Union[str, float, None]]:
    """
    Sınıflandırma hakkında detaylı bilgi verir.

    Bu fonksiyon, sınıflandırma sonucuna ek olarak:
    - Timestamp bilgisi
    - Bayrak varlığı
    - Alan değişim detayları
    - Hata durumları

    Debug ve analiz amaçlı kullanılır.

    Args:
        prev: Önceki telemetri verisi
        curr: Mevcut telemetri verisi

    Returns:
        Detaylı sınıflandırma bilgileri sözlüğü

    Örnek Çıktı:
        {
            "classification": "critical",
            "timestamp": 1234567890,
            "has_flag": false,
            "field_changes": {
                "speed": {
                    "previous": 100.0,
                    "current": 105.0,
                    "change_percent": 5.0
                }
            }
        }
    """
    try:
        # Ana sınıflandırmayı yap
        cls = classify(prev, curr)
        # Temel bilgileri topla
        info = {
            "classification": cls,
            "timestamp": curr.get("ts", None),
            "has_flag": "flag" in curr,
        }
        # Bayrak mesajları için ek bilgi
        if cls == "flag_only":
            info["flag_value"] = curr.get("flag", None)
        elif prev is not None:
            # Düzenli telemetri için değişim detayları
            critical_fields = ["speed", "pressure", "temperature"]
            changes = {}
            # Her kritik alan için değişim hesapla
            for field in critical_fields:
                if field in curr and field in prev:
                    try:
                        prev_val = prev[field]
                        curr_val = curr[field]

                        # Sayısal değerleri kontrol et
                        if isinstance(prev_val, (int, float)) and isinstance(
                            curr_val, (int, float)
                        ):
                            # Sıfıra bölme koruması
                            if abs(prev_val) < 1e-9:
                                prev_val = 1e-9

                            # Değişim yüzdesini hesapla
                            change = abs(curr_val - prev_val) / abs(prev_val)

                            # Değişim bilgilerini sakla
                            changes[field] = {
                                "previous": prev_val,
                                "current": curr_val,
                                "change_percent": change * 100,  # Yüzde olarak
                            }
                    except:
                        # Hatalı alanları atla
                        continue
                        # Değişim bilgilerini ekle
            info["field_changes"] = changes

        return info

    except Exception as e:
        # Hata durumunda hata bilgisi döner
        return {"classification": "error", "error": str(e)}


def is_critical_change(prev: Optional[Dict], curr: Optional[Dict], field: str, threshold: float = 0.02) -> bool:
    """
    Belirli bir alandaki değişimin kritik olup olmadığını kontrol eder.

    Args:
        prev: Önceki veri
        curr: Mevcut veri
        field: Kontrol edilecek alan
        threshold: Eşik değeri (varsayılan %2)

    Returns:
        Değişim kritikse True, değilse False
    """
    # Girdi doğrulama
    if prev is None or curr is None:
        return False
    
    if not isinstance(prev, dict) or not isinstance(curr, dict):
        return False
    
    if field not in prev or field not in curr:
        return False
    
    prev_val = prev[field]
    curr_val = curr[field]
    
    # Sayısal değer kontrolü
    if not isinstance(prev_val, (int, float)) or not isinstance(curr_val, (int, float)):
        return False
    
    # Sıfır değer kontrolü - sıfırdan küçük değişimler kritik değil
    if prev_val == 0:
        return curr_val > 0.1  # Sadece büyük değişimler kritik
    
    # Değişim yüzdesini hesapla
    change_percent = abs(curr_val - prev_val) / abs(prev_val)
    
    return change_percent >= threshold
