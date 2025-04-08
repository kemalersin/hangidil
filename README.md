# Hangi Dil API

Hangi Dil API, metinlerin hangi dilde yazıldığını tespit etmek için geliştirilmiş bir hizmettir. Bu API, langdetect kütüphanesini kullanarak metinleri analiz eder ve dilini tespit eder.

## Özellikler

- **Dil Tespiti**: Metinlerin hangi dilde yazıldığını algılar
- **Çoklu Dil Desteği**: 55 farklı dil için destek
- **Olasılık Analizi**: Her dil için olasılık değerleri
- **API Anahtarı Yönetimi**: Erişim kontrolü ve kullanım limitleri için API anahtarları
- **IP Tabanlı Kısıtlamalar**: IP bazlı rate limiting ve kullanım takibi
- **Admin Paneli**: Sistem yönetimi için kapsamlı bir yönetici arayüzü
- **Kullanım İstatistikleri**: API kullanımını takip etmek için detaylı raporlar

## Kurulum

### Gereksinimler

- Python 3.7 veya üstü
- MySQL / MariaDB veritabanı
- langdetect
- Flask

### Adımlar

1. Projeyi klonlayın:
```bash
git clone https://github.com/kemalersin/hangidil.git
cd hangidil
```

2. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

3. `.env` dosyasını oluşturun:
```
DB_HOST=localhost
DB_USER=kullaniciadi
DB_PASSWORD=sifre
DB_NAME=hangidil_api
SECRET_KEY=gizli_anahtar
ADMIN_PASSWORD=admin_sifresi
```

4. Veritabanını oluşturun:
```bash
mysql -u root -p
CREATE DATABASE hangidil_api;
```

5. API'yi başlatın:
```bash
python api_service.py --host 0.0.0.0 --port 5000
```

## Kullanım

### API Endpoint'leri

#### Dil Tespiti

```
POST /predict
```

**İstek Örneği:**
```json
{
  "text": "Dili tespit edilecek metin"
}
```

**Yanıt Örneği:**
```json
{
  "text": "Dili tespit edilecek metin",
  "detected_language": "tr",
  "language_probabilities": [
    {
      "lang": "tr",
      "probability": 0.9854
    },
    {
      "lang": "az",
      "probability": 0.0146
    }
  ],
  "usage_info": {
    "tokens_used": 5,
    "tokens_remaining": 9995,
    "unlimited": false,
    "using_api_key": true
  }
}
```

#### Toplu Dil Tespiti

```
POST /batch_predict
```

**İstek Örneği:**
```json
{
  "texts": ["Birinci metin", "Second text", "Troisième texte"]
}
```

#### Kullanım Bilgisi

```
GET /usage_info
```

### API Anahtarı Kullanımı

API'yi çağırırken, isteğinizde bir API anahtarı sağlayabilirsiniz:

```
curl -X POST "http://api.example.com/predict" \
     -H "Content-Type: application/json" \
     -H "X-API-Key: sizin_api_anahtariniz" \
     -d '{"text": "Dili tespit edilecek metin"}'
```

### İstek Limitleri

- IP başına 15 dakikada 15 istek
- API anahtarları için aylık token limiti (varsayılan: 100,000)
- IP adresleri için aylık token limiti (varsayılan: 10,000)

## Admin Paneli

Admin paneline erişmek için:

1. `/admin` adresine gidin
2. Admin şifresini girin (`.env` dosyasında ayarlanmış)

### Admin Paneli Özellikleri

- **API Anahtarı Yönetimi**: Yeni anahtarlar oluşturma, mevcut anahtarları düzenleme ve silme
- **IP Kullanımı**: IP bazlı kullanım istatistiklerini görüntüleme ve limitleri sıfırlama
- **Kullanım Özeti**: Genel API kullanımı hakkında istatistikler
- **Admin API**: Programlama yoluyla admin işlemlerini gerçekleştirme

## Desteklenen Diller

API, ISO 639-1 dil kodlarıyla aşağıdaki 55 dili desteklemektedir:

- Afrikaans (af)
- Arapça (ar)
- Bulgarca (bg)
- Bengalce (bn)
- Katalanca (ca)
- Çekçe (cs)
- Galce (cy)
- Danca (da)
- Almanca (de)
- Yunanca (el)
- İngilizce (en)
- İspanyolca (es)
- Estonca (et)
- Farsça (fa)
- Fince (fi)
- Fransızca (fr)
- Güceratça (gu)
- İbranice (he)
- Hintçe (hi)
- Hırvatça (hr)
- Macarca (hu)
- Endonezce (id)
- İtalyanca (it)
- Japonca (ja)
- Kannada (kn)
- Korece (ko)
- Litvanca (lt)
- Letonca (lv)
- Makedonca (mk)
- Malayalam (ml)
- Marathi (mr)
- Nepalce (ne)
- Felemenkçe (nl)
- Norveççe (no)
- Pencapça (pa)
- Lehçe (pl)
- Portekizce (pt)
- Romence (ro)
- Rusça (ru)
- Slovakça (sk)
- Slovence (sl)
- Somalice (so)
- Arnavutça (sq)
- İsveççe (sv)
- Svahili (sw)
- Tamil (ta)
- Telugu (te)
- Tay dili (th)
- Tagalog (tl)
- Türkçe (tr)
- Ukraynaca (uk)
- Urduca (ur)
- Vietnamca (vi)
- Çince (Basit) (zh-cn)
- Çince (Geleneksel) (zh-tw)

## Teknik Detaylar

### Mimari

- **API Servisi**: Flask kullanılarak geliştirilmiş RESTful API
- **Dil Tespiti**: langdetect kütüphanesi ile dil algılama
- **Veritabanı**: MySQL/MariaDB ile kullanıcı ve kullanım verileri yönetimi
- **Frontend**: HTML, CSS (Tailwind) ve JavaScript ile geliştirilen yönetici arayüzü

### Güvenlik Özellikleri

- API anahtarları ile erişim kontrolü
- IP bazlı rate limiting
- Admin arayüzü için şifre koruması
- Token tabanlı yetkilendirme

## Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.

## İletişim

Sorularınız veya önerileriniz için [info@apimapi.com](mailto:info@apimapi.com) adresine e-posta gönderebilirsiniz. 