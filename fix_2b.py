import re, shutil, os
p = "telegram/bot_handlers.py"
with open(p, encoding="utf-8") as f:
    c = f.read()

# لو payer_email معرّف مسبقاً، لا شيء نفعله
if "_fallback_email = f'customer" in c:
    print("⏭️  التعريف موجود مسبقاً — لا حاجة للإصلاح")
else:
    # نحقن التعريف قبل أول payload يستخدم 'payer_email': payer_email
    marker = "        payload = {\n            'action': 'SALE',"
    if marker not in c:
        print("⚠️ لم أجد بداية payload. أرسل grep لكلود.")
    else:
        inject = (
            "        # اختيار الايميل: الحقيقي ان كان صالحا، والا وهمي\n"
            "        import re as _re\n"
            "        _fallback_email = f'customer{int(time.time())}@invoice.com'\n"
            "        if customer_email and _re.match(r'^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$', customer_email):\n"
            "            payer_email = customer_email.strip().lower()\n"
            "        else:\n"
            "            payer_email = _fallback_email\n\n"
        )
        shutil.copy2(p, p + ".bak2")
        c = c.replace(marker, inject + marker, 1)
        with open(p, "w", encoding="utf-8") as f:
            f.write(c)
        print("✅ تم حقن تعريف payer_email قبل payload")
