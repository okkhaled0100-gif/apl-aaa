# ============================================
# 🛒 نظام سلة التسوق
# ============================================

from flask import Blueprint, request, jsonify, session, redirect, render_template
from datetime import datetime, timedelta
import random

from extensions import db
from firebase_utils import get_user_cart, save_user_cart, clear_user_cart, get_balance
from google.cloud import firestore
from security_utils import (
    require_session_user, get_session_user_id, log_security_event,
    sanitize_error_message
)
from encryption_utils import decrypt_data

# استيراد دالة إشعار التفاعلات
try:
    from notifications import send_activity_notification, send_order_email
except ImportError:
    send_activity_notification = lambda *args, **kwargs: None
    send_order_email = lambda *args, **kwargs: None

# إنشاء Blueprint
cart_bp = Blueprint('cart', __name__)

# سيتم تعيينها من app.py
bot = None
ADMIN_ID = None
limiter = None


def init_cart(app_bot, admin_id, app_limiter):
    """تهيئة متغيرات السلة"""
    global bot, ADMIN_ID, limiter
    bot = app_bot
    ADMIN_ID = admin_id
    limiter = app_limiter


@cart_bp.route('/cart')
def cart_page():
    """صفحة سلة التسوق"""
    # ✅ من Session فقط - لا نقبل user_id من URL
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/')
    
    balance = get_balance(user_id)
    return render_template('cart.html', user_id=user_id, balance=balance)


@cart_bp.route('/api/cart/add', methods=['POST'])
@require_session_user()
def api_cart_add():
    """إضافة منتج للسلة مع حجز المنتج - محمي من Authentication Bypass"""
    try:
        data = request.json
        user_id = get_session_user_id()  # من Session فقط، ليس من المستخدم
        product_id = data.get('product_id')
        buyer_details = data.get('buyer_details', '')
        
        if not user_id or not product_id:
            return jsonify({'status': 'error', 'message': 'بيانات ناقصة'})
        
        # التحقق من المنتج
        product_ref = db.collection('products').document(product_id)
        product_doc = product_ref.get()
        if not product_doc.exists:
            return jsonify({'status': 'error', 'message': 'المنتج غير موجود'})
        
        product = product_doc.to_dict()
        
        # منع إضافة منتج مباع
        if product.get('sold', False):
            return jsonify({'status': 'error', 'message': '❌ عذراً، هذا المنتج تم بيعه!'})
        
        # ✅ التحقق من الحجز (نظام جديد)
        now = datetime.utcnow()
        reserved_until = product.get('reserved_until')
        reserved_by = product.get('reserved_by')
        
        if reserved_until and reserved_by:
            # تحويل التاريخ إذا كان timestamp من Firebase
            if hasattr(reserved_until, 'timestamp'):
                reserved_until = datetime.utcfromtimestamp(reserved_until.timestamp())
            elif isinstance(reserved_until, str):
                reserved_until = datetime.fromisoformat(reserved_until.replace('Z', ''))
            
            # هل المنتج محجوز لشخص آخر والوقت لم ينتهِ؟
            if reserved_until > now and str(reserved_by) != str(user_id):
                remaining = int((reserved_until - now).total_seconds())
                minutes = remaining // 60
                seconds = remaining % 60
                return jsonify({
                    'status': 'error', 
                    'message': f'🔒 هذا المنتج محجوز لعميل آخر! حاول بعد {minutes}:{seconds:02d} دقيقة.'
                })
        
        cart = get_user_cart(user_id) or {}
        
        # التحقق من انتهاء السلة
        if cart.get('expires_at'):
            expires = cart['expires_at']
            if isinstance(expires, str):
                expires = datetime.fromisoformat(expires.replace('Z', ''))
            if expires < now:
                cart = {}
        
        # إنشاء سلة جديدة أو تحديث
        reservation_minutes = 5  # مدة الحجز بالدقائق
        reservation_time = now + timedelta(minutes=reservation_minutes)
        
        if not cart.get('items'):
            cart = {
                'items': [],
                'created_at': now.isoformat() + 'Z',
                'expires_at': reservation_time.isoformat() + 'Z',
                'status': 'active'
            }
        else:
            # تحديث وقت انتهاء السلة ليكون 5 دقائق من الآن
            cart['expires_at'] = reservation_time.isoformat() + 'Z'
        
        # حد أقصى لعدد المنتجات في السلة
        MAX_CART_ITEMS = 10
        if len(cart.get('items', [])) >= MAX_CART_ITEMS:
            return jsonify({'status': 'error', 'message': f'❌ الحد الأقصى للسلة {MAX_CART_ITEMS} منتجات'})

        # التحقق من عدم وجود المنتج في السلة
        existing_ids = [item['product_id'] for item in cart.get('items', [])]
        if product_id in existing_ids:
            return jsonify({'status': 'error', 'message': 'المنتج موجود في السلة بالفعل!'})
        
        # ✅ حجز المنتج في Firebase (Lock)
        product_ref.update({
            'reserved_by': user_id,
            'reserved_until': reservation_time.isoformat()
        })
        
        # إضافة المنتج للسلة
        cart_item = {
            'product_id': product_id,
            'name': product.get('item_name', 'منتج'),
            'price': float(product.get('price', 0)),
            'category': product.get('category', ''),
            'image_url': product.get('image_url', ''),
            'delivery_type': product.get('delivery_type', 'instant'),
            'buyer_instructions': product.get('buyer_instructions', ''),
            'buyer_details': buyer_details,
            'added_at': now.isoformat(),
            'reserved_until': reservation_time.isoformat()
        }
        cart['items'].append(cart_item)
        cart['updated_at'] = now.isoformat()
        
        # حفظ في Firebase
        save_user_cart(user_id, cart)
        
        # تحديث إحصائيات المنتج
        try:
            stats_ref = db.collection('cart_stats').document(product_id)
            stats_doc = stats_ref.get()
            if stats_doc.exists:
                stats_ref.update({'add_to_cart_count': firestore.Increment(1)})
            else:
                stats_ref.set({'product_id': product_id, 'add_to_cart_count': 1, 'purchase_count': 0})
        except:
            pass
        
        return jsonify({
            'status': 'success',
            'message': f'🛒✨ تم حجز المنتج لك لمدة {reservation_minutes} دقائق! أكمل الشراء بسرعة 🔥',
            'cart_count': len(cart['items']),
            'expires_at': reservation_time.isoformat() + 'Z'
        })
        
    except Exception as e:
        print(f"❌ خطأ في إضافة للسلة: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': 'حدث خطأ'})


@cart_bp.route('/api/cart/get')
@require_session_user()
def api_cart_get():
    """جلب محتويات السلة - محمي بالجلسة"""
    try:
        # ✅ من Session فقط - لا نقبل user_id من URL
        user_id = get_session_user_id()
        if not user_id:
            return jsonify({'status': 'error', 'message': 'يرجى تسجيل الدخول'}), 401
        
        cart = get_user_cart(str(user_id)) or {}
        
        if not cart or not cart.get('items'):
            return jsonify({'status': 'empty', 'message': 'السلة فارغة'})
        
        # التحقق من انتهاء الصلاحية
        now = datetime.utcnow()
        expires_at = cart.get('expires_at')
        if expires_at:
            if isinstance(expires_at, str):
                expires = datetime.fromisoformat(expires_at.replace('Z', ''))
            else:
                expires = expires_at
            if expires < now:
                clear_user_cart(str(user_id))
                return jsonify({'status': 'expired', 'message': 'انتهت صلاحية السلة'})
        
        # تحديث حالة المنتجات
        updated_items = []
        for item in cart['items']:
            product_doc = db.collection('products').document(item['product_id']).get()
            if product_doc.exists:
                product = product_doc.to_dict()
                item['sold'] = product.get('sold', False)
                item['current_price'] = float(product.get('price', item['price']))
                item['price_changed'] = item['current_price'] != item['price']
                updated_items.append(item)
            else:
                item['sold'] = True
                updated_items.append(item)
        
        cart['items'] = updated_items
        
        return jsonify({
            'status': 'success',
            'cart': cart
        })
        
    except Exception as e:
        print(f"❌ خطأ في جلب السلة: {e}")
        return jsonify({'status': 'error', 'message': 'حدث خطأ'})


@cart_bp.route('/api/cart/remove', methods=['POST'])
@require_session_user()
def api_cart_remove():
    """حذف منتج من السلة وإلغاء الحجز - محمي من IDOR"""
    try:
        data = request.json
        # ✅ إصلاح IDOR: نأخذ user_id من الجلسة فقط وليس من الطلب
        user_id = get_session_user_id()
        product_id = data.get('product_id')
        
        if not user_id:
            return jsonify({'status': 'error', 'message': 'يجب تسجيل الدخول'}), 401
        
        if not product_id:
            return jsonify({'status': 'error', 'message': 'معرف المنتج مطلوب'})
        
        cart = get_user_cart(user_id) or {}
        if not cart or not cart.get('items'):
            return jsonify({'status': 'error', 'message': 'السلة فارغة'})
        
        # حذف المنتج
        cart['items'] = [i for i in cart['items'] if i['product_id'] != product_id]
        cart['updated_at'] = datetime.utcnow().isoformat()
        
        # ✅ إلغاء حجز المنتج في Firebase
        try:
            product_ref = db.collection('products').document(product_id)
            product_doc = product_ref.get()
            if product_doc.exists:
                product_data = product_doc.to_dict()
                # تأكد أن الحجز للمستخدم الحالي فقط
                if str(product_data.get('reserved_by')) == str(user_id):
                    product_ref.update({
                        'reserved_by': None,
                        'reserved_until': None
                    })
        except Exception as e:
            print(f"⚠️ خطأ في إلغاء الحجز: {e}")
        
        # حفظ في Firebase
        save_user_cart(user_id, cart)
        
        return jsonify({
            'status': 'success',
            'message': 'تم حذف المنتج',
            'cart_count': len(cart['items'])
        })
        
    except Exception as e:
        print(f"❌ خطأ في حذف من السلة: {e}")
        return jsonify({'status': 'error', 'message': 'حدث خطأ'})




@cart_bp.route('/api/cart/checkout', methods=['POST'])
@require_session_user()
def api_cart_checkout():
    """إتمام شراء السلة - محمي من Race Condition و Authentication Bypass"""
    global bot, ADMIN_ID
    
    try:
        user_id = get_session_user_id()  # من Session فقط
        
        if not user_id:
            return jsonify({'status': 'error', 'message': 'معرف المستخدم مطلوب'}), 401
        
        # جلب السلة من Firebase
        cart = get_user_cart(user_id) or {}
        if not cart or not cart.get('items'):
            return jsonify({'status': 'error', 'message': 'السلة فارغة'})
        
        # ✅ التحقق من انتهاء مهلة الحجز
        now = datetime.utcnow()
        expires_at = cart.get('expires_at')
        if expires_at:
            if isinstance(expires_at, str):
                expires = datetime.fromisoformat(expires_at.replace('Z', ''))
            else:
                expires = expires_at
            if expires < now:
                # انتهت مهلة الحجز - نلغي الحجوزات ونفرغ السلة
                for item in cart.get('items', []):
                    try:
                        product_ref = db.collection('products').document(item['product_id'])
                        product_doc = product_ref.get()
                        if product_doc.exists:
                            product_data = product_doc.to_dict()
                            if str(product_data.get('reserved_by')) == str(user_id):
                                product_ref.update({'reserved_by': None, 'reserved_until': None})
                    except:
                        pass
                clear_user_cart(user_id)
                return jsonify({
                    'status': 'error', 
                    'message': '⏳ انتهت مهلة الحجز (5 دقائق)! يرجى إضافة المنتجات للسلة مرة أخرى.'
                })
        
        # تصفية المنتجات المتاحة
        available_items = []
        total = 0
        
        for item in cart['items']:
            product_doc = db.collection('products').document(item['product_id']).get()
            if product_doc.exists:
                product = product_doc.to_dict()
                if not product.get('sold', False):
                    # ✅ التحقق من أن الحجز للمستخدم الحالي
                    reserved_by = product.get('reserved_by')
                    if reserved_by and str(reserved_by) != str(user_id):
                        continue  # المنتج محجوز لشخص آخر
                    
                    item['product_data'] = product
                    item['current_price'] = float(product.get('price', item['price']))
                    total += item['current_price']
                    available_items.append(item)
        
        if not available_items:
            return jsonify({'status': 'error', 'message': 'لا توجد منتجات متاحة في السلة'})
        
        # ✅ استخدام Firestore Transaction لضمان عدم Race Condition
        def checkout_callback(transaction):
            """callback لتنفيذ الشراء بشكل آمن"""
            # اقرأ بيانات المستخدم
            user_ref = db.collection('users').document(user_id)
            user_snapshots = list(transaction.get_all([user_ref]))
            
            if not user_snapshots or not user_snapshots[0].exists:
                raise ValueError('المستخدم غير موجود')
            
            user_snapshot = user_snapshots[0]
            user_data = user_snapshot.to_dict()
            balance = float(user_data.get('balance', 0))
            bonus = float(user_data.get('balance_bonus', 0) or 0)

            # تحقق من الرصيد (الحقيقي + المكافأة)
            if balance + bonus < total:
                raise ValueError(f'رصيدك غير كافي! تحتاج {total - balance - bonus:.2f} ر.س إضافية')

            # الخصم: من الحقيقي أول، ثم المكافأة
            from_balance = min(balance, total)
            from_bonus = total - from_balance
            new_balance = balance - from_balance
            new_bonus = bonus - from_bonus
            transaction.update(user_ref, {
                'balance': new_balance,
                'balance_bonus': new_bonus,
                'last_purchase': firestore.SERVER_TIMESTAMP
            })
            
            # تحضير البيانات للمشتري
            buyer_name = user_data.get('name') or user_data.get('username') or user_data.get('first_name') or 'مستخدم'
            purchased_items_data = []
            order_ids = []
            
            # معالجة كل منتج
            for item in available_items:
                product = item['product_data']
                product_id = item['product_id']
                delivery_type = item.get('delivery_type', product.get('delivery_type', 'instant'))
                order_status = 'completed' if delivery_type == 'instant' else 'pending'
                
                # تحديث المنتج كمباع وإزالة الحجز
                product_ref = db.collection('products').document(product_id)
                transaction.update(product_ref, {
                    'sold': True,
                    'buyer_id': user_id,
                    'buyer_name': buyer_name,
                    'sold_at': firestore.SERVER_TIMESTAMP,
                    'reserved_by': None,
                    'reserved_until': None
                })
                
                # إنشاء الطلب
                order_id = f"ORD_{random.randint(100000, 999999)}"
                order_ref = db.collection('orders').document(order_id)
                transaction.set(order_ref, {
                    'buyer_id': user_id,
                    'buyer_name': buyer_name,
                    'item_name': product.get('item_name'),
                    'price': item['current_price'],
                    'hidden_data': product.get('hidden_data'),
                    'details': product.get('details', ''),
                    'category': product.get('category', ''),
                    'delivery_type': delivery_type,
                    'buyer_details': item.get('buyer_details', ''),
                    'buyer_instructions': item.get('buyer_instructions', ''),
                    'status': order_status,
                    'from_cart': True,
                    'created_at': firestore.SERVER_TIMESTAMP
                })
                
                order_ids.append(order_id)
                purchased_items_data.append({
                    'name': product.get('item_name'),
                    'price': item['current_price'],
                    'hidden_data': product.get('hidden_data'),
                    'order_id': order_id,
                    'delivery_type': delivery_type,
                    'buyer_details': item.get('buyer_details', '')
                })
                
                # تحديث إحصائيات
                try:
                    stats_ref = db.collection('cart_stats').document(product_id)
                    stats_snapshots = list(transaction.get_all([stats_ref]))
                    if stats_snapshots and stats_snapshots[0].exists:
                        current_count = stats_snapshots[0].get('purchase_count') or 0
                        transaction.update(stats_ref, {'purchase_count': current_count + 1})
                except:
                    pass
            
            return {
                'purchased_items': purchased_items_data,
                'new_balance': new_balance,
                'buyer_name': buyer_name,
                'order_ids': order_ids,
                'buyer_email': user_data.get('email', ''),
                'email_verified': user_data.get('email_verified', False)
            }
        
        # تنفيذ العملية بأمان
        try:
            @firestore.transactional
            def do_checkout(transaction):
                return checkout_callback(transaction)
            
            transaction = db.transaction()
            result = do_checkout(transaction)
        except ValueError as e:
            # خطأ متعلق بالأعمال (رصيد غير كافي، إلخ)
            return jsonify({'status': 'error', 'message': str(e)})
        
        # بعد نجاح العملية
        purchased_items = result['purchased_items']
        new_balance = result['new_balance']
        buyer_name = result['buyer_name']
        order_ids = result['order_ids']
        buyer_email = result.get('buyer_email', '')
        email_verified = result.get('email_verified', False)
        
        # حذف السلة من Firebase
        clear_user_cart(user_id)
        
        # فصل المنتجات الفورية عن اليدوية
        instant_items = [i for i in purchased_items if i.get('delivery_type') == 'instant']
        manual_items = [i for i in purchased_items if i.get('delivery_type') == 'manual']
        
        # إرسال البيانات للمشتري عبر البوت
        if bot:
            try:
                msg = "🎉 تم شراء سلتك بنجاح!\n\n"
                
                if instant_items:
                    msg += "⚡ منتجات تسليم فوري:\n"
                    for item in instant_items:
                        msg += f"📦 {item['name']}\n"
                        msg += f"💰 {item['price']} ر.س\n"
                        msg += f"🆔 #{item['order_id']}\n"
                        if item.get('hidden_data'):
                            # فك تشفير البيانات السرية قبل الإرسال
                            decrypted_data = decrypt_data(item['hidden_data'])
                            msg += f"🔐 البيانات:\n{decrypted_data}\n"
                        msg += "─────────────\n"
                
                if manual_items:
                    msg += "\n👨‍💼 منتجات تسليم يدوي (بانتظار التنفيذ):\n"
                    for item in manual_items:
                        msg += f"📦 {item['name']}\n"
                        msg += f"💰 {item['price']} ر.س\n"
                        msg += f"🆔 #{item['order_id']}\n"
                        msg += "⏳ سيتم تنفيذه قريباً\n"
                        msg += "─────────────\n"
                
                msg += f"\n💳 رصيدك المتبقي: {new_balance:.2f} ر.س"
                
                bot.send_message(int(user_id), msg)
            except Exception as e:
                print(f"⚠️ فشل إرسال رسالة للمشتري: {e}")
            
            # إشعار الأدمن والمشرفين للطلبات اليدوية
            if manual_items and ADMIN_ID:
                try:
                    import telebot
                    
                    # جلب قائمة المشرفين
                    admin_ids = [ADMIN_ID]  # المالك أولاً
                    try:
                        admins_ref = db.collection('admins').stream()
                        for admin_doc in admins_ref:
                            admin_data = admin_doc.to_dict()
                            admin_ids.append(int(admin_data['telegram_id']))
                    except:
                        pass
                    
                    for item in manual_items:
                        claim_markup = telebot.types.InlineKeyboardMarkup()
                        claim_markup.add(telebot.types.InlineKeyboardButton(
                            "📋 استلام الطلب", 
                            callback_data=f"claim_order_{item['order_id']}"
                        ))
                        
                        # رسالة بدون بيانات المشتري - ستظهر فقط بعد الاستلام
                        admin_msg = "🆕 طلب يدوي جديد!\n\n"
                        admin_msg += f"🆔 رقم الطلب: #{item['order_id']}\n"
                        admin_msg += f"📦 المنتج: {item['name']}\n"
                        admin_msg += f"💰 السعر: {item['price']} ر.س\n"
                        admin_msg += "\n🔒 بيانات المشتري ستظهر بعد الاستلام"
                        admin_msg += "\n👇 اضغط لاستلام الطلب"
                        
                        # إرسال لجميع المشرفين والمالك
                        for admin_id in admin_ids:
                            try:
                                bot.send_message(admin_id, admin_msg, reply_markup=claim_markup)
                            except Exception as e:
                                print(f"⚠️ فشل إرسال لـ {admin_id}: {e}")
                                
                except Exception as e:
                    print(f"⚠️ فشل إشعار الأدمنز: {e}")
            
            # إشعار عام للأدمن
            if ADMIN_ID:
                try:
                    admin_msg = "🛒 شراء سلة جديد!\n\n"
                    admin_msg += f"👤 المشتري: {buyer_name} ({user_id})\n"
                    admin_msg += f"📦 عدد المنتجات: {len(purchased_items)}\n"
                    admin_msg += f"⚡ فوري: {len(instant_items)} | 👨‍💼 يدوي: {len(manual_items)}\n"
                    admin_msg += f"💰 الإجمالي: {total:.2f} ر.س"
                    bot.send_message(ADMIN_ID, admin_msg)
                except:
                    pass
        
        # إرسال بيانات الطلب بالإيميل (إذا مربوط ومفعّل)
        if buyer_email and email_verified:
            email_items = []
            for item in purchased_items:
                ei = {
                    'name': item.get('name', ''),
                    'price': item.get('price', 0),
                    'order_id': item.get('order_id', ''),
                    'delivery_type': item.get('delivery_type', 'instant')
                }
                if item.get('hidden_data') and item.get('delivery_type') == 'instant':
                    ei['hidden_data'] = decrypt_data(item['hidden_data'])
                email_items.append(ei)
            send_order_email(buyer_email, email_items, total, new_balance)

        # تسجيل الحدث الأمني
        log_security_event('CHECKOUT_SUCCESS', user_id, f'الإجمالي: {total}, المنتجات: {len(purchased_items)}')
        
        # إرسال إشعار لقناة التفاعلات
        telegram_username = session.get('telegram_username', '')
        product_names = ', '.join([item.get('name', 'منتج')[:20] for item in purchased_items[:3]])
        send_activity_notification('purchase', user_id, telegram_username, {
            'product': product_names,
            'price': total
        })
        
        return jsonify({
            'status': 'success',
            'message': 'تم الشراء بنجاح!',
            'purchased_count': len(purchased_items),
            'total': total,
            'new_balance': new_balance,
            'order_ids': order_ids
        })
        
    except Exception as e:
        error_msg = sanitize_error_message(str(e))
        log_security_event('CHECKOUT_ERROR', user_id, error_msg)
        print(f"❌ خطأ في إتمام الشراء: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': 'حدث خطأ في إتمام الشراء'})


@cart_bp.route('/api/cart/count')
@require_session_user()
def api_cart_count():
    """جلب عدد منتجات السلة - محمي بالجلسة"""
    # ✅ من Session فقط
    user_id = get_session_user_id()
    if not user_id:
        return jsonify({'count': 0})
    
    cart = get_user_cart(str(user_id)) or {}
    count = len(cart.get('items', []))
    return jsonify({'count': count})
