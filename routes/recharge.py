# نسخ من wallet routes
from flask import Blueprint, render_template, request, jsonify
import time
import secrets
import string
from extensions import db, logger, SITE_URL
from firebase_utils import get_balance, get_toggle
from payment import create_wallet_payment
from notifications import notify_new_charge
from security_utils import require_session_user, get_session_user_id

recharge_bp = Blueprint('recharge', __name__, url_prefix='/wallet')

# تخزين الفواتير
merchant_invoices = {}

# ============ عرض صفحة الشحن ============
@recharge_bp.route('/recharge')
def recharge_page():
    """عرض صفحة الشحن الجديدة"""
    return render_template('recharge.html')

# ============ API: جلب الرصيد ============
@recharge_bp.route('/api/balance')
@require_session_user()
def get_wallet_balance():
    """جلب رصيد الحساب الحالي"""
    try:
        user_id = get_session_user_id()
        balance = get_balance(user_id)
        
        return jsonify({
            'success': True,
            'balance': balance,
            'currency': 'SAR'
        })
    except Exception as e:
        logger.error(f"خطأ في جلب الرصيد: {e}")
        return jsonify({'success': False, 'error': str(e)})

# ============ شحن مباشر (الطريقة الحالية) ============
@recharge_bp.route('/recharge', methods=['POST'])
@require_session_user()
def direct_recharge():
    """شحن مباشر من EdfaPay"""
    try:
        # قراءة البيانات من JSON أو form
        data = request.get_json() or request.form
        amount = str(data.get('amount', '')).strip()
        user_id = get_session_user_id()
        user_name = f"User {user_id}"
        
        # التحقق من المبلغ
        if not amount:
            return jsonify({'success': False, 'error': 'المبلغ مطلوب'})
        
        try:
            amount_int = int(float(amount))
            if amount_int < 10 or amount_int > 50000:
                return jsonify({'success': False, 'error': 'المبلغ يجب أن يكون بين 10 و 50000 ريال'})
        except (ValueError, TypeError):
            return jsonify({'success': False, 'error': 'المبلغ يجب أن يكون رقماً'})
        
        # إنشاء طلب دفع في EdfaPay
        result = create_wallet_payment(user_id, amount_int)
        
        if result['success']:
            # إشعار المالك
            notify_new_charge(user_id, amount_int, method='edfapay', username=user_name, async_mode=True)
            
            return jsonify({
                'success': True,
                'payment_url': result['payment_url'],
                'order_id': result.get('order_id')
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'فشل إنشاء طلب الدفع')
            })
    
    except Exception as e:
        logger.error(f"❌ خطأ في direct_recharge: {e}")
        return jsonify({'success': False, 'error': 'حدث خطأ على السيرفر'})

# ============ إنشاء رابط شحن (جديد) ============
@recharge_bp.route('/create-link', methods=['POST'])
@require_session_user()
def create_recharge_link():
    """إنشاء رابط شحن يشاركه أي شخص"""
    try:
        # قراءة البيانات من JSON أو form
        data = request.get_json() or request.form
        amount = str(data.get('amount', '')).strip()
        user_id = get_session_user_id()

        # فحص مفتاح التحكم: إنشاء الروابط متوقف؟
        if not get_toggle('payment_links_create', True):
            return jsonify({'success': False, 'error': 'إنشاء روابط الدفع متوقف مؤقتاً'})

        # حماية: روابط الدفع متاحة للتجار فقط
        try:
            from firebase_utils import is_wholesaler as _is_wh
            if not _is_wh(user_id):
                return jsonify({'success': False, 'error': 'إنشاء روابط الدفع متاح للتجار فقط'})
        except Exception as _e:
            logger.error(f"خطأ في التحقق من صفة التاجر: {_e}")
            return jsonify({'success': False, 'error': 'تعذّر التحقق من الصلاحية'})

        # حماية: يجب توثيق الإيميل لإنشاء روابط الدفع (لاستقبال الإشعارات)
        try:
            _udoc = db.collection('users').document(str(user_id)).get()
            if not (_udoc.exists and _udoc.to_dict().get('email_verified', False)):
                return jsonify({'success': False, 'error': 'يجب توثيق بريدك الإلكتروني أولاً لإنشاء روابط الدفع'})
        except Exception as _e:
            logger.error(f"خطأ في التحقق من الإيميل: {_e}")
            return jsonify({'success': False, 'error': 'تعذّر التحقق من توثيق البريد'})

        # جلب اسم التاجر الحقيقي من Firestore (name > first_name > fallback)
        user_name = None
        try:
            _udoc = db.collection('users').document(str(user_id)).get()
            if _udoc.exists:
                _ud = _udoc.to_dict()
                user_name = _ud.get('name') or _ud.get('first_name') or _ud.get('username')
        except Exception as _e:
            logger.error(f"خطأ في جلب اسم التاجر: {_e}")
        if not user_name:
            user_name = f"User {user_id}"

        # اسم المنتج (اختياري - يظهر للعميل)
        product_name = str(data.get('product_name', '')).strip()[:60]

        # التحقق من المبلغ
        if not amount:
            return jsonify({'success': False, 'error': 'المبلغ مطلوب'})
        
        try:
            amount_int = int(float(amount))
            if amount_int < 10 or amount_int > 500:  # MAX_LINK_500
                return jsonify({'success': False, 'error': 'المبلغ يجب أن يكون بين 10 و 500 ريال'})
        except (ValueError, TypeError):
            return jsonify({'success': False, 'error': 'المبلغ يجب أن يكون رقماً'})
        
        # إنشاء معرف فريد قصير للفاتورة
        short_id = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        invoice_id = f"L{short_id}"  # مثلاً: La1b2c3d4
        
        # بيانات الفاتورة (merchant_* لتوافق مسار الدفع)
        invoice_data = {
            'invoice_id': invoice_id,
            'merchant_id': user_id,                    # من سينال الرصيد (يقرأه مسار الدفع)
            'merchant_name': user_name,                # الاسم الحقيقي
            'recipient_id': user_id,
            'recipient_name': user_name,
            'product_name': product_name,              # اسم المنتج
            'amount': amount_int,
            'status': 'pending',
            'created_at': time.time(),
            'expires_at': time.time() + 3600,          # ساعة واحدة
            'is_recharge_link': True,                  # تمييز الرابط
            'created_by': user_id,
            'description': f"رابط شحن من {user_name}"
        }
        
        # حفظ في Firebase
        try:
            db.collection('merchant_invoices').document(invoice_id).set(invoice_data)
            merchant_invoices[invoice_id] = invoice_data
        except Exception as e:
            logger.error(f"خطأ في حفظ في Firebase: {e}")
            return jsonify({'success': False, 'error': 'خطأ في حفظ الرابط'})
        
        # إنشاء الرابط
        link = f"{SITE_URL}/invoice/{invoice_id}"
        
        return jsonify({
            'success': True,
            'link': link,
            'invoice_id': invoice_id,
            'amount': amount_int
        })
    
    except Exception as e:
        logger.error(f"❌ خطأ في create_recharge_link: {e}")
        return jsonify({'success': False, 'error': 'حدث خطأ على السيرفر'})
