#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Middleware - طبقة الحماية المتقدمة
============================================
يحتوي على:
1. CSRF Protection - حماية النماذج
2. OTP للسحب - رمز تحقق عبر Telegram
3. تنبيهات تسجيل الدخول الجديد
4. كشف تغير الجهاز/IP
"""

import os
import time
import hashlib
import logging
from functools import wraps
from flask import session, request, jsonify
from datetime import datetime
import json

logger = logging.getLogger(__name__)

# ==================== 1. CSRF Protection ====================

# تخزين مؤقت لـ CSRF tokens
_csrf_tokens = {}  # {session_id: {'token': 'xxx', 'created_at': timestamp}}
CSRF_TOKEN_EXPIRY = 3600  # ساعة واحدة

def generate_csrf_token():
    """توليد CSRF token آمن"""
    try:
        # إنشاء token عشوائي
        token = hashlib.sha256(os.urandom(32)).hexdigest()
        
        # تخزينه في Session
        session['csrf_token'] = token
        session['csrf_created_at'] = time.time()
        
        return token
    except Exception as e:
        logger.error(f"خطأ في توليد CSRF token: {e}")
        return None


def get_csrf_token():
    """الحصول على CSRF token الحالي أو إنشاء جديد"""
    token = session.get('csrf_token')
    created_at = session.get('csrf_created_at', 0)
    
    # التحقق من صلاحية الـ token
    if token and (time.time() - created_at) < CSRF_TOKEN_EXPIRY:
        return token
    
    # إنشاء token جديد
    return generate_csrf_token()


def validate_csrf_token(token):
    """التحقق من صحة CSRF token"""
    stored_token = session.get('csrf_token')
    created_at = session.get('csrf_created_at', 0)
    
    # التحقق من وجود الـ token
    if not stored_token or not token:
        return False
    
    # التحقق من الصلاحية
    if (time.time() - created_at) > CSRF_TOKEN_EXPIRY:
        return False
    
    # مقارنة آمنة
    return hashlib.sha256(token.encode()).digest() == hashlib.sha256(stored_token.encode()).digest()


# ==================== Double Submit Cookie Protection ====================
# حماية إضافية: التحقق من تطابق Token في Cookie و Header/Form

CSRF_COOKIE_NAME = 'csrf_double_submit'

def set_csrf_cookie(response, token=None):
    """
    إضافة CSRF token في Cookie للـ Double Submit protection
    يُستخدم في @app.after_request
    """
    if token is None:
        token = session.get('csrf_token', '')
    
    if token:
        response.set_cookie(
            CSRF_COOKIE_NAME,
            token,
            httponly=False,  # يجب أن يكون قابل للقراءة من JavaScript
            secure=True,
            samesite='Strict',
            max_age=3600  # ساعة واحدة
        )
    return response


def validate_double_submit():
    """
    التحقق من تطابق CSRF token في Cookie مع Header/Form
    Returns: True إذا تطابق، False إذا لم يتطابق
    """
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME, '')
    
    # الحصول على الـ token من الـ request
    request_token = (
        request.form.get('csrf_token') or
        request.headers.get('X-CSRF-Token') or
        (request.get_json(silent=True) or {}).get('csrf_token') or
        ''
    )
    
    if not cookie_token or not request_token:
        return False
    
    # مقارنة آمنة
    return hashlib.sha256(cookie_token.encode()).digest() == hashlib.sha256(request_token.encode()).digest()


def csrf_protect(f):
    """Decorator لحماية الـ routes من CSRF مع Double Submit"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # الحصول على الـ token من الـ request
            token = (
                request.form.get('csrf_token') or
                request.headers.get('X-CSRF-Token') or
                (request.get_json(silent=True) or {}).get('csrf_token')
            )
            
            # التحقق الأول: Session token
            session_valid = validate_csrf_token(token)
            
            # التحقق الثاني: Double Submit Cookie
            double_submit_valid = validate_double_submit()
            
            # يجب أن ينجح أحدهما على الأقل
            if not session_valid and not double_submit_valid:
                logger.warning(f"🚫 CSRF فاشل (Double Submit) من {request.remote_addr}")
                return jsonify({'success': False, 'message': 'فشل التحقق من الأمان. يرجى إعادة تحميل الصفحة'}), 403
        
        return f(*args, **kwargs)
    return decorated_function


# ==================== 2. تنبيهات تسجيل الدخول الجديد ====================

def get_device_fingerprint():
    """الحصول على بصمة الجهاز من الـ request"""
    user_agent = request.headers.get('User-Agent', '')
    accept_lang = request.headers.get('Accept-Language', '')
    
    # إنشاء hash للبصمة
    fingerprint = hashlib.md5(f"{user_agent}|{accept_lang}".encode()).hexdigest()[:16]
    
    return {
        'fingerprint': fingerprint,
        'user_agent': user_agent[:200],  # تقليص الحجم
        'ip': get_real_ip(),
        'timestamp': time.time()
    }


def get_real_ip():
    """الحصول على IP الحقيقي (مع مراعاة الـ proxy)"""
    # Cloudflare
    if request.headers.get('CF-Connecting-IP'):
        return request.headers.get('CF-Connecting-IP')
    
    # X-Forwarded-For
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    
    # X-Real-IP
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    
    # الـ IP المباشر
    return request.remote_addr


def detect_new_login(db, user_id, bot=None):
    """
    كشف تسجيل دخول من جهاز جديد
    
    Returns:
        dict: {'is_new': bool, 'device_info': dict}
    """
    try:
        current_device = get_device_fingerprint()
        user_id = str(user_id)
        
        # جلب الأجهزة المسجلة للمستخدم
        user_ref = db.collection('users').document(user_id)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return {'is_new': False, 'device_info': current_device}
        
        user_data = user_doc.to_dict()
        known_devices = user_data.get('known_devices', [])
        
        # البحث عن الجهاز الحالي
        is_new_device = True
        for device in known_devices:
            if device.get('fingerprint') == current_device['fingerprint']:
                is_new_device = False
                break
        
        # إذا كان جهاز جديد
        if is_new_device:
            # إضافة الجهاز للقائمة
            known_devices.append(current_device)
            
            # الاحتفاظ بآخر 10 أجهزة فقط
            if len(known_devices) > 10:
                known_devices = known_devices[-10:]
            
            # تحديث قاعدة البيانات
            user_ref.update({
                'known_devices': known_devices,
                'last_login': datetime.now(),
                'last_login_ip': current_device['ip']
            })
            
            # إرسال تنبيه للمستخدم
            if bot:
                try:
                    send_new_login_alert(bot, user_id, current_device, user_data.get('name', 'المستخدم'))
                except Exception as e:
                    logger.error(f"خطأ في إرسال تنبيه الدخول: {e}")
        
        return {'is_new': is_new_device, 'device_info': current_device}
    
    except Exception as e:
        logger.error(f"خطأ في كشف الجهاز الجديد: {e}")
        return {'is_new': False, 'device_info': {}}


def send_new_login_alert(bot, user_id, device_info, user_name):
    """إرسال تنبيه بتسجيل دخول من جهاز جديد"""
    try:
        # تحليل User-Agent
        user_agent = device_info.get('user_agent', '')
        
        # تحديد نوع الجهاز
        if 'Mobile' in user_agent or 'Android' in user_agent or 'iPhone' in user_agent:
            device_type = '📱 هاتف'
        elif 'Tablet' in user_agent or 'iPad' in user_agent:
            device_type = '📟 تابلت'
        else:
            device_type = '💻 كمبيوتر'
        
        # تحديد المتصفح
        if 'Chrome' in user_agent:
            browser = 'Chrome'
        elif 'Firefox' in user_agent:
            browser = 'Firefox'
        elif 'Safari' in user_agent:
            browser = 'Safari'
        elif 'Edge' in user_agent:
            browser = 'Edge'
        else:
            browser = 'متصفح آخر'
        
        # الوقت
        login_time = datetime.now().strftime('%Y-%m-%d %H:%M')
        
        message = f"""
🔔 <b>تنبيه أمني - تسجيل دخول جديد</b>

مرحباً {user_name}،

تم تسجيل الدخول لحسابك من جهاز جديد:

{device_type} • {browser}
🌐 IP: {device_info.get('ip', 'غير معروف')}
🕐 الوقت: {login_time}

✅ إذا كان هذا أنت، تجاهل هذه الرسالة.

⚠️ إذا لم تكن أنت:
1. قم بتغيير كود الدخول فوراً
2. فعّل التحقق بخطوتين (2FA)
3. تواصل معنا للمساعدة
"""
        bot.send_message(int(user_id), message, parse_mode='HTML')
        logger.info(f"✅ تم إرسال تنبيه دخول جديد للمستخدم {user_id}")
        
    except Exception as e:
        logger.error(f"خطأ في إرسال تنبيه الدخول: {e}")


# ==================== 4. Session Security ====================

def bind_session_to_ip():
    """ربط الجلسة بالـ IP (اختياري - يمكن تعطيله)"""
    if 'session_ip' not in session:
        session['session_ip'] = get_real_ip()
        return True
    
    if session['session_ip'] != get_real_ip():
        # IP تغير - قد يكون اختراق
        logger.warning(f"⚠️ تغير IP للجلسة: {session['session_ip']} -> {get_real_ip()}")
        return False
    
    return True


def refresh_session():
    """تحديث بيانات الجلسة بشكل دوري"""
    session['last_activity'] = time.time()
    
    # تجديد CSRF token كل 30 دقيقة
    csrf_created = session.get('csrf_created_at', 0)
    if (time.time() - csrf_created) > 1800:  # 30 دقيقة
        generate_csrf_token()


# ==================== Context Processor ====================

def inject_security_context():
    """
    دالة لحقن متغيرات الأمان في جميع القوالب
    
    الاستخدام في app.py:
    from security_middleware import inject_security_context
    
    @app.context_processor
    def security_context():
        return inject_security_context()
    """
    return {
        'csrf_token': get_csrf_token
    }


# ==================== 5. CSP Headers - Content Security Policy ====================

def add_security_headers(response):
    """
    إضافة Security Headers لحماية الموقع
    
    الاستخدام:
    @app.after_request
    def after_request(response):
        return add_security_headers(response)
    """
    # Content Security Policy
    csp_policy = "; ".join([
        "default-src 'self'",
        # السماح بـ Scripts من المصادر الموثوقة
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com https://code.jquery.com",
        # السماح بـ Styles
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://unpkg.com",
        # الخطوط
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com data:",
        # الصور
        "img-src 'self' data: https: blob:",
        # الاتصالات (API)
        "connect-src 'self' https://api.telegram.org",
        # منع التضمين في iframe (حماية Clickjacking)
        "frame-ancestors 'none'",
        # قاعدة URL
        "base-uri 'self'",
        # النماذج
        "form-action 'self'"
    ])
    
    response.headers['Content-Security-Policy'] = csp_policy
    
    # X-Content-Type-Options - منع تخمين نوع المحتوى
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # X-Frame-Options - حماية من Clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # X-XSS-Protection - حماية إضافية من XSS (للمتصفحات القديمة)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer-Policy - التحكم في معلومات الـ Referrer
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions-Policy - تعطيل APIs غير مستخدمة
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # HSTS - فرض HTTPS (في الإنتاج)
    if os.environ.get('RENDER') or os.environ.get('PRODUCTION'):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response


# ==================== 6. Security Logging - تسجيل الأحداث الأمنية ====================


# Logger خاص بالأمان
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

# إنشاء handler للملف إذا لم يكن موجوداً
if not security_logger.handlers:
    try:
        # محاولة الكتابة في ملف
        file_handler = logging.FileHandler('security.log', encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        security_logger.addHandler(file_handler)
    except Exception:
        # في حالة عدم إمكانية الكتابة، استخدم stdout
        pass

# أنواع الأحداث الأمنية
class SecurityEvent:
    LOGIN_SUCCESS = 'LOGIN_SUCCESS'
    LOGIN_FAILED = 'LOGIN_FAILED'
    LOGIN_NEW_DEVICE = 'LOGIN_NEW_DEVICE'
    LOGOUT = 'LOGOUT'
    PASSWORD_CHANGE = 'PASSWORD_CHANGE'
    WALLET_CHANGE = 'WALLET_CHANGE'
    PURCHASE = 'PURCHASE'
    WITHDRAWAL_REQUEST = 'WITHDRAWAL_REQUEST'
    WITHDRAWAL_APPROVED = 'WITHDRAWAL_APPROVED'
    WITHDRAWAL_REJECTED = 'WITHDRAWAL_REJECTED'
    ADMIN_LOGIN = 'ADMIN_LOGIN'
    ADMIN_LOGIN_FAILED = 'ADMIN_LOGIN_FAILED'
    ADMIN_ACTION = 'ADMIN_ACTION'
    SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY'
    RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED'
    CSRF_FAILED = 'CSRF_FAILED'
    IDOR_ATTEMPT = 'IDOR_ATTEMPT'
    TWO_FA_ENABLED = 'TWO_FA_ENABLED'
    TWO_FA_DISABLED = 'TWO_FA_DISABLED'


# تخزين مؤقت للأحداث (للحفظ في Firestore لاحقاً)
_security_events_buffer = []
_db_reference = None

def set_security_db(db):
    """تعيين مرجع قاعدة البيانات للتسجيل"""
    global _db_reference
    _db_reference = db


def log_security_event(event_type, user_id=None, ip=None, details=None, severity='INFO'):
    """
    تسجيل حدث أمني
    
    Args:
        event_type: نوع الحدث من SecurityEvent
        user_id: معرف المستخدم (اختياري)
        ip: عنوان IP (اختياري - يُستنتج تلقائياً)
        details: تفاصيل إضافية (dict أو string)
        severity: مستوى الخطورة (INFO, WARNING, CRITICAL)
    """
    try:
        # الحصول على IP إذا لم يُمرر
        if ip is None:
            try:
                ip = get_real_ip()
            except:
                ip = 'unknown'
        
        # إنشاء سجل الحدث
        event_record = {
            'event_type': event_type,
            'user_id': str(user_id) if user_id else None,
            'ip': ip,
            'details': details if isinstance(details, str) else json.dumps(details, ensure_ascii=False) if details else None,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'user_agent': request.headers.get('User-Agent', '')[:200] if request else None
        }
        
        # تسجيل في الـ logger
        log_message = f"EVENT: {event_type} | USER: {user_id} | IP: {ip} | SEVERITY: {severity}"
        if details:
            log_message += f" | DETAILS: {event_record['details']}"
        
        if severity == 'CRITICAL':
            security_logger.critical(log_message)
        elif severity == 'WARNING':
            security_logger.warning(log_message)
        else:
            security_logger.info(log_message)
        
        # محاولة الحفظ في Firestore
        if _db_reference:
            try:
                _db_reference.collection('security_logs').add({
                    **event_record,
                    'timestamp': datetime.now()  # Firestore timestamp
                })
            except Exception as e:
                logger.error(f"خطأ في حفظ سجل الأمان في Firestore: {e}")
        
        # إرسال تنبيه للأحداث الحرجة
        if severity == 'CRITICAL':
            _send_critical_alert(event_record)
        
        return True
        
    except Exception as e:
        logger.error(f"خطأ في تسجيل الحدث الأمني: {e}")
        return False


def _send_critical_alert(event_record):
    """إرسال تنبيه للأحداث الحرجة (داخلي)"""
    # يمكن إضافة إرسال تنبيه عبر Telegram هنا


def get_security_logs(user_id=None, event_type=None, limit=100):
    """
    جلب سجلات الأمان
    
    Args:
        user_id: فلتر بالمستخدم (اختياري)
        event_type: فلتر بنوع الحدث (اختياري)
        limit: عدد السجلات
    
    Returns:
        list: قائمة السجلات
    """
    if not _db_reference:
        return []
    
    try:
        query = _db_reference.collection('security_logs')
        
        if user_id:
            query = query.where('user_id', '==', str(user_id))
        
        if event_type:
            query = query.where('event_type', '==', event_type)
        
        query = query.order_by('timestamp', direction='DESCENDING').limit(limit)
        
        logs = []
        for doc in query.stream():
            log_data = doc.to_dict()
            log_data['id'] = doc.id
            logs.append(log_data)
        
        return logs
        
    except Exception as e:
        logger.error(f"خطأ في جلب سجلات الأمان: {e}")
        return []


# دالة مساعدة للتسجيل السريع
def log_login_success(user_id, ip=None):
    """تسجيل دخول ناجح"""
    log_security_event(SecurityEvent.LOGIN_SUCCESS, user_id, ip)


def log_login_failed(user_id, ip=None, reason=None):
    """تسجيل دخول فاشل"""
    log_security_event(SecurityEvent.LOGIN_FAILED, user_id, ip, {'reason': reason}, 'WARNING')


def log_admin_login(admin_id, ip=None):
    """تسجيل دخول أدمن"""
    log_security_event(SecurityEvent.ADMIN_LOGIN, admin_id, ip, severity='WARNING')


def log_suspicious_activity(user_id=None, ip=None, activity=None):
    """تسجيل نشاط مشبوه"""
    log_security_event(SecurityEvent.SUSPICIOUS_ACTIVITY, user_id, ip, {'activity': activity}, 'CRITICAL')


def log_purchase(user_id, product_id, amount, ip=None):
    """تسجيل عملية شراء"""
    log_security_event(SecurityEvent.PURCHASE, user_id, ip, {
        'product_id': product_id,
        'amount': amount
    })


def log_withdrawal(user_id, amount, wallet, ip=None):
    """تسجيل طلب سحب"""
    log_security_event(SecurityEvent.WITHDRAWAL_REQUEST, user_id, ip, {
        'amount': amount,
        'wallet': wallet[:10] + '...' if wallet else None  # إخفاء جزء من المحفظة
    }, 'WARNING')
