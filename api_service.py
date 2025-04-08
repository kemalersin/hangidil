from flask import Flask, request, jsonify, g, render_template, session, redirect, url_for
import argparse
from mysql.connector import pooling
from datetime import datetime
import ipaddress
import hashlib
import math
import os
import functools
import logging
from dotenv import load_dotenv
from langdetect import detect, detect_langs, DetectorFactory

# Tutarlı sonuçlar için seed ayarla
DetectorFactory.seed = 0

# .env dosyasını yükle
load_dotenv()

# Flask uygulaması
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24))

# Statik dosya sunumu güvenlik kontrolü
@app.route('/static/js/admin.js')
def admin_js():
    # Eğer admin girişi yapılmamışsa erişimi reddet
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Yetkisiz erişim'}), 403
    
    # Admin girişi yapılmışsa dosyayı sun
    return app.send_static_file('js/admin.js')

# Admin statik dosyalarını korumak için genel bir middleware
@app.before_request
def protect_admin_assets():
    # İstek yolu statik dosyalara mı?
    if request.path.startswith('/static/'):
        # Admin ile ilgili dosyaları kontrol et
        admin_patterns = [
            '/static/js/admin',  # admin.js veya admin ile başlayan js dosyaları
            '/static/css/admin', # admin.css veya admin ile başlayan css dosyaları
            '/static/img/admin', # admin ile ilgili resimler
            '/static/admin'      # admin klasöründeki tüm dosyalar
        ]
        
        # İstek yolu admin desenleriyle eşleşiyor mu?
        if any(request.path.startswith(pattern) for pattern in admin_patterns):
            # Admin girişi yapılmamışsa erişimi reddet
            if not session.get('admin_logged_in'):
                return jsonify({'error': 'Yetkisiz erişim'}), 403

# Loglama
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global değişkenler
DB_POOL = None

# Admin şifresi
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")  # Güvenlik için .env dosyasından alınmalı

# Veritabanı işlemleri
def init_db_pool():
    """MySQL bağlantı havuzu oluştur"""
    global DB_POOL
    
    try:
        DB_POOL = pooling.MySQLConnectionPool(
            pool_name="api_pool",
            pool_size=5,
            host=os.getenv("DB_HOST", "localhost"),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", ""),
            database=os.getenv("DB_NAME", "hangidil_api")
        )
        logger.info("Veritabanı bağlantı havuzu oluşturuldu")
        
        # Veritabanı şemasını kontrol et ve gerekirse oluştur
        create_schema()
    except Exception as e:
        logger.error(f"Veritabanı bağlantı havuzu oluşturulurken hata: {e}")
        raise

def create_schema():
    """Gerekli tabloları oluştur"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor()
    
    try:
        # API Keys tablosu
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INT AUTO_INCREMENT PRIMARY KEY,
            api_key VARCHAR(64) NOT NULL UNIQUE,
            description VARCHAR(255),
            is_unlimited BOOLEAN DEFAULT FALSE,
            unlimited_ips TEXT,
            monthly_token_limit INT DEFAULT 1000,
            tokens_used INT DEFAULT 0,
            auto_reset BOOLEAN DEFAULT TRUE,
            last_reset_date DATETIME,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
        """)
        
        # IP bazlı kısıtlama takibi için yeni tablo
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_rate_limits (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL UNIQUE,
            monthly_token_limit INT DEFAULT 10000,
            tokens_used INT DEFAULT 0,
            request_count INT DEFAULT 0,
            last_request_time TIMESTAMP,
            last_reset_date DATETIME,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
        """)
        
        # API kullanım logları tablosu
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_usage_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            api_key_id INT,
            request_ip VARCHAR(45),
            endpoint VARCHAR(255),
            text_length INT,
            tokens_used INT,
            is_successful BOOLEAN,
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL
        )
        """)
        
        conn.commit()
        logger.info("Veritabanı şeması kontrol edildi/oluşturuldu")
    except Exception as e:
        logger.error(f"Veritabanı şeması oluştururken hata: {e}")
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

def get_api_key_info(api_key):
    """API key bilgilerini veritabanından al"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # API key'i kontrol et
        cursor.execute(
            "SELECT * FROM api_keys WHERE api_key = %s",
            (api_key,)
        )
        key_info = cursor.fetchone()
        
        # Key varsa ve otomatik sıfırlama aktifse, son sıfırlama tarihinden 30 gün geçmiş mi kontrol et
        if key_info and key_info.get('auto_reset', True):
            current_datetime = datetime.now()
            
            # Son sıfırlama tarihi yoksa, oluşturulma tarihini kullan
            reference_datetime = key_info['last_reset_date']
            if reference_datetime is None and key_info['created_at']:
                reference_datetime = key_info['created_at']
            
            # 30 gün geçmişse tokenleri sıfırla
            if reference_datetime and (current_datetime - reference_datetime).days >= 30:
                cursor.execute(
                    "UPDATE api_keys SET tokens_used = 0, last_reset_date = %s WHERE id = %s",
                    (current_datetime, key_info['id'])
                )
                conn.commit()
                key_info['tokens_used'] = 0
                key_info['last_reset_date'] = current_datetime
                logger.info(f"API key {key_info['id']} için tokenler 30 günlük periyod sonunda sıfırlandı. Sıfırlama zamanı: {current_datetime}")
        
        return key_info
    except Exception as e:
        logger.error(f"API key bilgisi alınırken hata: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def update_token_usage(api_key_id, tokens_used):
    """Kullanılan token sayısını güncelle"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE api_keys SET tokens_used = tokens_used + %s WHERE id = %s",
            (tokens_used, api_key_id)
        )
        conn.commit()
        logger.info(f"Token kullanımı güncellendi: api_key_id={api_key_id}, tokens_used={tokens_used}")
    except Exception as e:
        logger.error(f"Token kullanımı güncellenirken hata: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def log_api_usage(api_key_id, request_ip, endpoint, text_length, tokens_used, is_successful, error_message=None):
    """API kullanımını logla"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO api_usage_logs (api_key_id, request_ip, endpoint, text_length, tokens_used, is_successful, error_message) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (api_key_id, request_ip, endpoint, text_length, tokens_used, is_successful, error_message)
        )
        conn.commit()
    except Exception as e:
        logger.error(f"API kullanımı loglanırken hata: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def calculate_tokens(text):
    """Metin için gereken token sayısını hesapla (her 4 karakter için 1 token)"""
    return math.ceil(len(text) / 4)

def is_ip_allowed(client_ip, unlimited_ips):
    """IP adresinin sınırsız listesinde olup olmadığını kontrol et"""
    if not unlimited_ips:
        return False
    
    ip_list = [ip.strip() for ip in unlimited_ips.split(',')]
    
    try:
        client_ip_obj = ipaddress.ip_address(client_ip)
        
        for ip_range in ip_list:
            if '/' in ip_range:  # CIDR notasyonu
                if client_ip_obj in ipaddress.ip_network(ip_range, strict=False):
                    return True
            else:  # Tek IP
                if client_ip_obj == ipaddress.ip_address(ip_range):
                    return True
        
        return False
    except ValueError:
        logger.error(f"Geçersiz IP adresi formatı: {client_ip} veya {unlimited_ips}")
        return False

def get_or_create_ip_info(ip_address):
    """IP adresi için kullanım bilgilerini al veya oluştur"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # IP adresini kontrol et
        cursor.execute(
            "SELECT * FROM ip_rate_limits WHERE ip_address = %s",
            (ip_address,)
        )
        ip_info = cursor.fetchone()
        
        # IP bilgisi yoksa oluştur
        if not ip_info:
            current_datetime = datetime.now()
            cursor.execute(
                """
                INSERT INTO ip_rate_limits 
                (ip_address, monthly_token_limit, tokens_used, request_count, last_reset_date) 
                VALUES (%s, %s, %s, %s, %s)
                """,
                (ip_address, 10000, 0, 0, current_datetime)
            )
            conn.commit()
            
            cursor.execute(
                "SELECT * FROM ip_rate_limits WHERE ip_address = %s",
                (ip_address,)
            )
            ip_info = cursor.fetchone()
        
        # Son sıfırlama tarihinden 30 gün geçmiş mi kontrol et
        if ip_info and ip_info['last_reset_date'] is not None:
            current_datetime = datetime.now()
            reference_datetime = ip_info['last_reset_date']
            
            # 30 gün geçmişse tokenleri sıfırla
            if (current_datetime - reference_datetime).days >= 30:
                cursor.execute(
                    "UPDATE ip_rate_limits SET tokens_used = 0, last_reset_date = %s WHERE id = %s",
                    (current_datetime, ip_info['id'])
                )
                conn.commit()
                ip_info['tokens_used'] = 0
                ip_info['last_reset_date'] = current_datetime
                logger.info(f"IP {ip_address} için tokenler 30 günlük periyod sonunda sıfırlandı. Sıfırlama zamanı: {current_datetime}")
        
        return ip_info
    except Exception as e:
        logger.error(f"IP bilgisi alınırken hata: {e}")
        conn.rollback()
        return None
    finally:
        cursor.close()
        conn.close()

def update_ip_token_usage(ip_id, tokens_used):
    """IP için kullanılan token sayısını güncelle"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE ip_rate_limits SET tokens_used = tokens_used + %s WHERE id = %s",
            (tokens_used, ip_id)
        )
        conn.commit()
        logger.info(f"IP için token kullanımı güncellendi: ip_id={ip_id}, tokens_used={tokens_used}")
    except Exception as e:
        logger.error(f"IP token kullanımı güncellenirken hata: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def update_ip_request_count(ip_id):
    """IP için istek sayısını güncelle ve son istek zamanını kaydet"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE ip_rate_limits SET request_count = request_count + 1, last_request_time = NOW() WHERE id = %s",
            (ip_id,)
        )
        conn.commit()
        logger.info(f"IP için istek sayısı güncellendi: ip_id={ip_id}")
    except Exception as e:
        logger.error(f"IP istek sayısı güncellenirken hata: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def reset_ip_request_count(ip_id):
    """IP için istek sayısını sıfırla (15 dakikalık periyod geçtikten sonra)"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE ip_rate_limits SET request_count = 0 WHERE id = %s",
            (ip_id,)
        )
        conn.commit()
        logger.info(f"IP için istek sayısı sıfırlandı: ip_id={ip_id}")
    except Exception as e:
        logger.error(f"IP istek sayısı sıfırlanırken hata: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def can_ip_make_request(ip_info):
    """IP adresinin 15 dakikada 15 istekten fazla yapmadığını kontrol et"""
    if not ip_info or not ip_info['last_request_time']:
        return True
    
    last_request = ip_info['last_request_time']
    now = datetime.now()
    diff = now - last_request
    
    # 15 dakika (900 saniye) geçtiyse istek sayısını sıfırla
    if diff.total_seconds() > 900:
        reset_ip_request_count(ip_info['id'])
        return True
    
    # 15 dakika içinde 15 istekten az yapmışsa izin ver
    return ip_info['request_count'] < 15

def log_ip_request(ip_address, endpoint, text_length, tokens_used, is_successful, error_message=None):
    """API key olmadan yapılan kullanımı logla"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO api_usage_logs (api_key_id, request_ip, endpoint, text_length, tokens_used, is_successful, error_message) VALUES (NULL, %s, %s, %s, %s, %s, %s)",
            (ip_address, endpoint, text_length, tokens_used, is_successful, error_message)
        )
        conn.commit()
    except Exception as e:
        logger.error(f"IP kullanımı loglanırken hata: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

# Admin işlemleri için decorator
def admin_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # Token tabanlı yetkilendirme (API istekleri için)
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            if token == ADMIN_PASSWORD:
                # API isteği için JSON yanıt hazırla
                return f(*args, **kwargs)
        
        # Session tabanlı yetkilendirme (tarayıcı istekleri için)
        if session.get('admin_logged_in'):
            # Tarayıcıdan gelen normal istekler
            return f(*args, **kwargs)
        
        # Her iki yöntemle de giriş başarısız oldu, yetkisiz erişim hatası döndür
        if request.headers.get('Accept') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"error": "Bu endpoint'e erişim için admin yetkisi gerekiyor."}), 401
        else:
            # Tarayıcı istekleri için bile JSON hatası döndür, yönlendirme yapma
            return jsonify({"error": "Yetkisiz erişim. Admin girişi yapmalısınız."}), 401
            
    return decorated_function

# Güncellenen API yetkilendirme decoratoru
def require_api_key(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # Admin kontrolü - admin istekleri tüm sınırlamalardan muaf
        admin_password = os.getenv("ADMIN_PASSWORD")
        provided_password = request.headers.get('Admin-Password')
        
        if admin_password and provided_password == admin_password:
            # Admin olarak işaretle ve sınırsız yetki ver
            g.is_admin = True
            g.is_unlimited = True
            g.using_api_key = False
            g.admin_request = True
            return f(*args, **kwargs)
        
        # Standart API key veya IP bazlı yetkilendirme
        api_key = request.headers.get('X-API-Key')
        
        # Gerçek istemci IP'sini al
        client_ip = get_client_ip()
        
        # API key varsa önceki sistemle işlem yap
        if api_key:
            key_info = get_api_key_info(api_key)
            
            if not key_info:
                return jsonify({"error": "Geçersiz API anahtarı"}), 401
            
            # Sınırsız API key veya izin verilen IP adres kontrolü
            is_unlimited = key_info['is_unlimited'] or is_ip_allowed(client_ip, key_info['unlimited_ips'])
            
            # Kullanım bilgilerini g nesnesine kaydet
            g.api_key_id = key_info['id']
            g.is_unlimited = is_unlimited
            g.tokens_used = key_info['tokens_used']
            g.monthly_token_limit = key_info['monthly_token_limit']
            g.using_api_key = True
            g.admin_request = False
        
        # API key yoksa IP bazlı sınırlamaları kontrol et
        else:
            ip_info = get_or_create_ip_info(client_ip)
            
            if not ip_info:
                return jsonify({"error": "IP adresi bilgisi alınamadı"}), 500
            
            # IP adresinin istek sınırını kontrol et
            if not can_ip_make_request(ip_info):
                return jsonify({
                    "error": "Hız sınırına ulaşıldı",
                    "message": "15 dakika içinde en fazla 15 istek yapabilirsiniz"
                }), 429
            
            # Kullanım bilgilerini g nesnesine kaydet
            g.ip_id = ip_info['id']
            g.is_unlimited = False
            g.tokens_used = ip_info['tokens_used']
            g.monthly_token_limit = ip_info['monthly_token_limit']
            g.using_api_key = False
            g.client_ip = client_ip
            g.admin_request = False
        
        return f(*args, **kwargs)
    return decorated


# API Endpoints
@app.route('/health', methods=['GET'])
def health_check():
    """Servisin çalışıp çalışmadığını kontrol etmek için basit bir endpoint"""
    return jsonify({"status": "healthy"})

@app.route('/predict', methods=['POST'])
@require_api_key
def predict():
    """Metnin dilini tespit et ve JSON yanıtı döndür"""
    # İstek gövdesinden metni al
    data = request.get_json(force=True)
    
    if 'text' not in data:
        return jsonify({"error": "Lütfen 'text' parametresi ekleyin"}), 400
    
    text = data['text']
    tokens_needed = calculate_tokens(text)
    
    # Gerçek istemci IP'sini al
    client_ip = get_client_ip()
    
    endpoint = '/predict'
    
    # Admin isteği veya sınırsız değilse token kontrolü yap
    if not g.is_unlimited:
        tokens_remaining = g.monthly_token_limit - g.tokens_used
        
        if tokens_needed > tokens_remaining:
            if g.using_api_key:
                log_api_usage(g.api_key_id, client_ip, endpoint, len(text), 0, False, 
                             f"Yetersiz token: {tokens_needed} gerekli, {tokens_remaining} kaldı")
            else:
                log_ip_request(client_ip, endpoint, len(text), 0, False, 
                             f"Yetersiz token: {tokens_needed} gerekli, {tokens_remaining} kaldı")
            
            return jsonify({
                "error": "Yetersiz token kredisi",
                "tokens_needed": tokens_needed,
                "tokens_remaining": tokens_remaining
            }), 403
    
    try:
        # IP bazlı istek limiti için sayacı güncelle (Admin değilse ve API key kullanmıyorsa)
        if not g.using_api_key and not getattr(g, 'admin_request', False):
            update_ip_request_count(g.ip_id)
    
        # Dil tespiti yap
        detected_language = detect(text)
        detected_probabilities = detect_langs(text)
        
        # Sonuçları hazırla
        results = {
            "text": text,
            "detected_language": detected_language,
            "language_probabilities": [{"lang": str(prob).split(':')[0], 
                                      "probability": float(str(prob).split(':')[1])} 
                                     for prob in detected_probabilities]
        }
            
        # Kullanımı güncelle (Admin değilse ve sınırsız değilse)
        if not g.is_unlimited and not getattr(g, 'admin_request', False):
            if g.using_api_key:
                update_token_usage(g.api_key_id, tokens_needed)
            else:
                update_ip_token_usage(g.ip_id, tokens_needed)
        
        # Kullanımı logla (Admin isteklerini de loglama amacıyla kaydedelim)
        if getattr(g, 'admin_request', False):
            log_ip_request(client_ip, f"{endpoint} (admin)", len(text), 0, True)
        elif g.using_api_key:
            log_api_usage(g.api_key_id, client_ip, endpoint, len(text), tokens_needed, True)
        else:
            log_ip_request(client_ip, endpoint, len(text), tokens_needed, True)
        
        # Kullanım bilgilerini ekle
        results["usage_info"] = {
            "tokens_used": tokens_needed if not getattr(g, 'admin_request', False) else 0,
            "unlimited": g.is_unlimited,
            "using_api_key": g.using_api_key,
            "admin_request": getattr(g, 'admin_request', False)
        }
        
        if not g.is_unlimited and not getattr(g, 'admin_request', False):
            results["usage_info"]["tokens_remaining"] = g.monthly_token_limit - g.tokens_used - tokens_needed
    
        return jsonify(results)
    
    except Exception as e:
        logger.error(f"Dil tespiti sırasında hata: {str(e)}")
        if getattr(g, 'admin_request', False):
            log_ip_request(client_ip, f"{endpoint} (admin)", len(text), 0, False, str(e))
        elif g.using_api_key:
            log_api_usage(g.api_key_id, client_ip, endpoint, len(text), 0, False, str(e))
        else:
            log_ip_request(client_ip, endpoint, len(text), 0, False, str(e))
        
        return jsonify({"error": "İşlem sırasında bir hata oluştu"}), 500

@app.route('/batch_predict', methods=['POST'])
@require_api_key
def batch_predict():
    """Birden fazla metnin dilini tespit et ve JSON yanıtı döndür"""
    # İstek gövdesinden metinleri al
    data = request.get_json(force=True)
    
    if 'texts' not in data or not isinstance(data['texts'], list):
        return jsonify({"error": "Lütfen 'texts' listesi ekleyin"}), 400
    
    texts = data['texts']
    
    # Gerçek istemci IP'sini al
    client_ip = get_client_ip()
    
    endpoint = '/batch_predict'
    
    # Toplam token ihtiyacını hesapla
    total_length = sum(len(text) for text in texts)
    total_tokens_needed = sum(calculate_tokens(text) for text in texts)
    
    # Admin isteği veya sınırsız değilse token kontrolü yap
    if not g.is_unlimited:
        tokens_remaining = g.monthly_token_limit - g.tokens_used
        
        if total_tokens_needed > tokens_remaining:
            if g.using_api_key:
                log_api_usage(g.api_key_id, client_ip, endpoint, total_length, 0, False, 
                             f"Yetersiz token: {total_tokens_needed} gerekli, {tokens_remaining} kaldı")
            else:
                log_ip_request(client_ip, endpoint, total_length, 0, False, 
                             f"Yetersiz token: {total_tokens_needed} gerekli, {tokens_remaining} kaldı")
            
            return jsonify({
                "error": "Yetersiz token kredisi",
                "tokens_needed": total_tokens_needed,
                "tokens_remaining": tokens_remaining
            }), 403
    
    try:
        # IP bazlı istek limiti için sayacı güncelle (Admin değilse ve API key kullanmıyorsa)
        if not g.using_api_key and not getattr(g, 'admin_request', False):
            update_ip_request_count(g.ip_id)
    
        # Her metin için dil tespiti yap
        all_results = []
        for text in texts:
            detected_language = detect(text)
            detected_probabilities = detect_langs(text)
            
            result = {
                "text": text,
                "detected_language": detected_language,
                "language_probabilities": [{"lang": str(prob).split(':')[0], 
                                          "probability": float(str(prob).split(':')[1])} 
                                         for prob in detected_probabilities]
            }
            all_results.append(result)
    
        # Kullanımı güncelle (Admin değilse ve sınırsız değilse)
        if not g.is_unlimited and not getattr(g, 'admin_request', False):
            if g.using_api_key:
                update_token_usage(g.api_key_id, total_tokens_needed)
            else:
                update_ip_token_usage(g.ip_id, total_tokens_needed)
        
        # Kullanımı logla (Admin isteklerini de loglama amacıyla kaydedelim)
        if getattr(g, 'admin_request', False):
            log_ip_request(client_ip, f"{endpoint} (admin)", total_length, 0, True)
        elif g.using_api_key:
            log_api_usage(g.api_key_id, client_ip, endpoint, total_length, total_tokens_needed, True)
        else:
            log_ip_request(client_ip, endpoint, total_length, total_tokens_needed, True)
        
        # Yanıtı hazırla
        response = {
            "results": all_results,
            "usage_info": {
                "tokens_used": total_tokens_needed if not getattr(g, 'admin_request', False) else 0,
                "unlimited": g.is_unlimited,
                "using_api_key": g.using_api_key,
                "admin_request": getattr(g, 'admin_request', False)
            }
        }
        
        if not g.is_unlimited and not getattr(g, 'admin_request', False):
            response["usage_info"]["tokens_remaining"] = g.monthly_token_limit - g.tokens_used - total_tokens_needed
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Toplu dil tespiti sırasında hata: {str(e)}")
        if getattr(g, 'admin_request', False):
            log_ip_request(client_ip, f"{endpoint} (admin)", total_length, 0, False, str(e))
        elif g.using_api_key:
            log_api_usage(g.api_key_id, client_ip, endpoint, total_length, 0, False, str(e))
        else:
            log_ip_request(client_ip, endpoint, total_length, 0, False, str(e))
        
        return jsonify({"error": "İşlem sırasında bir hata oluştu"}), 500

@app.route('/usage_info', methods=['GET'])
@require_api_key
def usage_info():
    """API key veya IP kullanım bilgilerini döndür"""
    try:
        info = {
            "is_unlimited": g.is_unlimited,
            "tokens_used": g.tokens_used,
            "using_api_key": g.using_api_key
        }
        
        if not g.is_unlimited:
            info["monthly_token_limit"] = g.monthly_token_limit
            info["tokens_remaining"] = g.monthly_token_limit - g.tokens_used
        
        # IP bazlı bilgiler (API key kullanılmıyorsa)
        if not g.using_api_key:
            # Gerçek istemci IP'sini al
            client_ip = get_client_ip()
                
            ip_info = get_or_create_ip_info(client_ip)
            if ip_info:
                info["request_count"] = ip_info["request_count"]
                info["rate_limit"] = {
                    "max_requests": 15,
                    "time_window_minutes": 15
                }
        
        return jsonify(info)
    
    except Exception as e:
        logger.error(f"Kullanım bilgisi alınırken hata: {str(e)}")
        return jsonify({"error": "İşlem sırasında bir hata oluştu"}), 500

@app.route('/admin')
def admin_panel():
    """Admin paneli"""
    error = request.args.get('error')
    error_message = None
    
    if error == 'yetkisiz_erisim':
        error_message = "Yetkisiz erişim. Lütfen tekrar giriş yapın."
    
    return render_template('admin.html', logged_in=session.get('admin_logged_in', False), error=error_message)

@app.route('/admin/login', methods=['POST'])
def admin_login():
    """Admin giriş işlemi"""
    password = request.form.get('password')
    if password == ADMIN_PASSWORD:
        session['admin_logged_in'] = True
        return redirect(url_for('admin_panel'))
    return render_template('admin.html', logged_in=False, error="Geçersiz şifre!")

@app.route('/admin/logout')
def admin_logout():
    """Admin çıkış işlemi"""
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_panel'))

@app.route('/admin/keys')
@admin_required
def list_api_keys():
    """API anahtarlarını listele"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT * FROM api_keys ORDER BY created_at DESC")
        api_keys = cursor.fetchall()
        return jsonify({"api_keys": api_keys})
    except Exception as e:
        logger.error(f"API anahtarları listelenirken hata: {e}")
        return jsonify({"error": "API anahtarları alınırken bir hata oluştu."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/keys/<int:key_id>', methods=['GET'])
@admin_required
def get_api_key(key_id):
    """Belirli bir ID'ye sahip API anahtarı bilgilerini getir"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT * FROM api_keys WHERE id = %s", (key_id,))
        api_key = cursor.fetchone()
        
        if not api_key:
            return jsonify({"error": "API anahtarı bulunamadı."}), 404
            
        return jsonify({"api_key": api_key})
    except Exception as e:
        logger.error(f"API anahtarı bilgileri alınırken hata: {e}")
        return jsonify({"error": "API anahtarı bilgileri alınırken bir hata oluştu."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/keys/<int:key_id>', methods=['DELETE'])
@admin_required
def delete_api_key(key_id):
    """API anahtarını sil"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM api_keys WHERE id = %s", (key_id,))
        conn.commit()
        
        if cursor.rowcount > 0:
            return jsonify({"message": "API anahtarı başarıyla silindi."})
        return jsonify({"error": "API anahtarı bulunamadı."}), 404
    except Exception as e:
        logger.error(f"API anahtarı silinirken hata: {e}")
        conn.rollback()
        return jsonify({"error": "API anahtarı silinirken bir hata oluştu."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/keys', methods=['POST'])
@admin_required
def create_api_key():
    """Yeni API anahtarı oluştur"""
    data = request.json
    
    description = data.get('description', '')
    monthly_token_limit = data.get('monthly_token_limit', 100000)
    is_unlimited = data.get('is_unlimited', False)
    auto_reset = data.get('auto_reset', True)
    
    # Yeni API anahtarı oluştur (32 karakterlik)
    api_key = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
    current_datetime = datetime.now()
    
    conn = DB_POOL.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO api_keys (api_key, description, monthly_token_limit, is_unlimited, auto_reset, tokens_used, last_reset_date) VALUES (%s, %s, %s, %s, %s, 0, %s)",
            (api_key, description, monthly_token_limit, is_unlimited, auto_reset, current_datetime)
        )
        conn.commit()
        
        return jsonify({"message": "API anahtarı başarıyla oluşturuldu.", "api_key": api_key})
    except Exception as e:
        logger.error(f"API anahtarı oluşturulurken hata: {e}")
        conn.rollback()
        return jsonify({"error": "API anahtarı oluşturulurken bir hata oluştu."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/list_ip_usage')
@admin_required
def list_ip_usage():
    """IP kullanım bilgilerini listele"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT * FROM ip_rate_limits ORDER BY request_count DESC")
        ip_usage = cursor.fetchall()
        return jsonify({"ip_usage": ip_usage})
    except Exception as e:
        logger.error(f"IP kullanım bilgileri listelenirken hata: {e}")
        return jsonify({"error": "IP kullanım bilgileri alınırken bir hata oluştu."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/keys/<int:key_id>', methods=['PUT'])
@admin_required
def update_api_key(key_id):
    """API anahtarı özelliklerini güncelle"""
    data = request.json
    
    description = data.get('description')
    is_unlimited = data.get('is_unlimited')
    auto_reset = data.get('auto_reset')
    monthly_token_limit = data.get('monthly_token_limit')
    
    conn = DB_POOL.get_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Öncelikle API anahtarının var olup olmadığını kontrol et
        cursor.execute("SELECT * FROM api_keys WHERE id = %s", (key_id,))
        key_exists = cursor.fetchone()
        
        if not key_exists:
            logger.warning(f"API anahtarı bulunamadı: key_id={key_id}")
            return jsonify({"error": "API anahtarı bulunamadı."}), 404
        
        logger.info(f"API anahtarı bulundu, güncelleniyor: {key_exists}")
        
        # Güncellenecek alanları ve değerleri hazırla
        update_fields = []
        update_values = []
        
        if description is not None:
            update_fields.append("description = %s")
            update_values.append(description)
            
        if is_unlimited is not None:
            update_fields.append("is_unlimited = %s")
            update_values.append(is_unlimited)
            
        if auto_reset is not None:
            update_fields.append("auto_reset = %s")
            update_values.append(auto_reset)
            
        if monthly_token_limit is not None:
            update_fields.append("monthly_token_limit = %s")
            update_values.append(monthly_token_limit)
        
        # Güncellenecek alan yoksa hata döndür
        if not update_fields:
            return jsonify({"error": "Güncellenecek alan belirtilmedi."}), 400
        
        # SQL sorgusunu oluştur
        sql = f"UPDATE api_keys SET {', '.join(update_fields)} WHERE id = %s"
        update_values.append(key_id)
        
        logger.info(f"Güncelleme SQL: {sql}, değerler: {update_values}")
        cursor.execute(sql, update_values)
        conn.commit()
        
        # API anahtarı zaten var olduğu kontrol edildi, bu nedenle rowcount kontrolü yapmadan başarılı yanıt dönüyoruz
        return jsonify({"message": "API anahtarı başarıyla güncellendi."})
    except Exception as e:
        logger.error(f"API anahtarı güncellenirken hata: {e}")
        conn.rollback()
        return jsonify({"error": "API anahtarı güncellenirken bir hata oluştu."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/reset_ip_limits/<string:ip_address>', methods=['POST'])
@admin_required
def reset_ip_limits(ip_address):
    """IP adresinin limitlerini sıfırla"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor()
    current_datetime = datetime.now()
    
    try:
        cursor.execute(
            "UPDATE ip_rate_limits SET tokens_used = 0, request_count = 0, last_reset_date = %s WHERE ip_address = %s",
            (current_datetime, ip_address)
        )
        conn.commit()
        
        if cursor.rowcount > 0:
            return jsonify({"message": f"{ip_address} için kullanım limitleri başarıyla sıfırlandı."})
        return jsonify({"error": "IP adresi bulunamadı."}), 404
    except Exception as e:
        logger.error(f"IP limitleri sıfırlanırken hata: {e}")
        conn.rollback()
        return jsonify({"error": "IP limitleri sıfırlanırken bir hata oluştu."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/usage_summary')
@admin_required
def usage_summary():
    """API kullanım özetini al"""
    conn = DB_POOL.get_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Genel istatistikler
        summary = {
            "total_api_keys": 0,
            "total_ips": 0,
            "today_requests": 0,
            "monthly_requests": 0,
            "top_api_keys": [],
            "top_ips": []
        }
        
        # Toplam API anahtarı sayısı
        cursor.execute("SELECT COUNT(*) as count FROM api_keys")
        result = cursor.fetchone()
        summary["total_api_keys"] = result["count"] if result else 0
        
        # Toplam IP adresi sayısı
        cursor.execute("SELECT COUNT(*) as count FROM ip_rate_limits")
        result = cursor.fetchone()
        summary["total_ips"] = result["count"] if result else 0
        
        # Bugünkü istek sayısı
        cursor.execute("SELECT COUNT(*) as count FROM api_usage_logs WHERE DATE(created_at) = CURDATE()")
        result = cursor.fetchone()
        summary["today_requests"] = result["count"] if result else 0
        
        # Son 30 gündeki istek sayısı
        cursor.execute("SELECT COUNT(*) as count FROM api_usage_logs WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)")
        result = cursor.fetchone()
        summary["monthly_requests"] = result["count"] if result else 0
        
        # En çok kullanılan API anahtarları (top 5)
        cursor.execute("""
            SELECT api_key_id, COUNT(*) as usage_count 
            FROM api_usage_logs 
            WHERE api_key_id IS NOT NULL
            GROUP BY api_key_id 
            ORDER BY usage_count DESC 
            LIMIT 5
        """)
        summary["top_api_keys"] = cursor.fetchall()
        
        # En çok istek yapan IP'ler (top 5)
        cursor.execute("""
            SELECT request_ip, COUNT(*) as usage_count 
            FROM api_usage_logs 
            GROUP BY request_ip 
            ORDER BY usage_count DESC 
            LIMIT 5
        """)
        summary["top_ips"] = cursor.fetchall()
        
        return jsonify(summary)
    except Exception as e:
        logger.error(f"Kullanım özeti alınırken hata: {e}")
        return jsonify({"error": "Kullanım özeti alınırken bir hata oluştu."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/')
def index():
    """Ana sayfa - API kullanım kılavuzu"""
    return render_template('index.html')

# Proxy arkasındaki gerçek istemci IP'sini almak için helper fonksiyon
def get_client_ip():
    """
    İstemcinin gerçek IP adresini döndürür.
    
    Proxy sunucuları, load balancer'lar veya reverse proxy arkasında çalışan
    uygulamalar için gerçek istemci IP'sini tespit etmeye çalışır.
    
    Öncelik sırası:
    1. CF-Connecting-IP header'ı (Cloudflare)
    2. True-Client-IP header'ı (Cloudflare alternatif)
    3. X-Forwarded-For header'ı (proxy sunucular tarafından eklenir)
    4. X-Real-IP header'ı (Nginx gibi reverse proxy'ler tarafından eklenir)
    5. X-Client-IP header'ı (bazı proxy'ler tarafından eklenir)
    6. Flask'ın remote_addr değeri (doğrudan bağlantılarda)
    
    X-Forwarded-For birden fazla IP içeriyorsa, en baştaki IP (gerçek istemci IP'si) alınır.
    """
    # Tüm olası header'ları kontrol et
    headers = [
        'HTTP_CF_CONNECTING_IP',  # Cloudflare
        'HTTP_TRUE_CLIENT_IP',    # Cloudflare alternatif
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'HTTP_X_CLIENT_IP',
        'REMOTE_ADDR'
    ]
    
    for header in headers:
        ip = request.environ.get(header)
        if ip:
            # X-Forwarded-For header'ı virgülle ayrılmış IP listesi içerebilir
            if ',' in ip:
                ip = ip.split(',')[0].strip()
            return ip
    
    # Hiçbir header bulunamazsa varsayılan olarak remote_addr'i döndür
    return request.remote_addr

if __name__ == "__main__":
    # Argüman ayrıştırıcı
    parser = argparse.ArgumentParser(description="Dil tespiti API")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="API host adresi")
    parser.add_argument("--port", type=int, default=5000, help="API port numarası")
    parser.add_argument("--watch", action="store_true", help="Dosya değişikliklerini izle ve otomatik yeniden başlat")
    args = parser.parse_args()
    
    # Veritabanını başlat
    init_db_pool()
    
    # Çalışma modunu al
    env = os.getenv('FLASK_ENV', 'production')
    
    if env == 'development':
        # Geliştirme modu
        logger.info("Uygulama geliştirme modunda başlatılıyor...")
        app.run(host=args.host, port=args.port, debug=True)
    else:
        # Üretim modu - waitress WSGI sunucusu kullanılıyor
        try:
            from waitress import serve
            logger.info(f"Uygulama üretim modunda waitress ile başlatılıyor (port: {args.port})...")
            serve(app, host=args.host, port=args.port, threads=8, trusted_proxy='*')
        except ImportError:
            logger.warning("Waitress yüklü değil, pip install waitress ile kurabilirsiniz.")
            logger.warning("Şimdilik geliştirme sunucusu kullanılıyor, üretim ortamında kullanmayın!")
            app.run(host=args.host, port=args.port)