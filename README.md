# Web Intelligence Analyzer 🔍

**أداة ذكية لجمع معلومات النطاقات والبريد الإلكتروني**

## المميزات ✨

### 🌐 معلومات النطاق (Domain)
- بيانات Whois المفصلة
- سجلات DNS كاملة
- معلومات IP والموقع الجغرافي
- بيانات شهادات SSL
- التاريخ من Wayback Machine
- فحص الأمان

### 📧 معلومات البريد الإلكتروني (Email)
- التحقق من صحة البريد
- فحص التسريبات (Have I Been Pwned)
- معلومات المجال المرتبط
- الحسابات المرتبطة
- تقييم مستوى الخطر

### 📊 التقارير
- تقارير PDF احترافية
- ملفات JSON مفصلة
- جداول CSV
- رسوم بيانية وإحصائيات

## التثبيت 🔧

```bash
git clone https://github.com/mhr63559-eng/kep.git
cd kep
pip install -r requirements.txt
```

## الاستخدام 🚀

### تحليل نطاق:
```bash
python3 main.py --domain example.com
```

### تحليل بريد:
```bash
python3 main.py --email user@example.com
```

### تحليل كامل مع تقرير:
```bash
python3 main.py --domain example.com --email user@example.com --report
```

### تحليل متقدم مع تفاصيل:
```bash
python3 main.py --domain example.com --verbose --report
```

## الخيارات 📋

```
--domain, -d      : اسم النطاق (مثل: example.com)
--email, -e       : البريد الإلكتروني (مثل: user@example.com)
--report, -r      : إنشاء تقرير PDF
--json, -j        : إنشاء ملف JSON
--csv, -c         : إنشاء ملف CSV
--verbose, -v     : عرض تفاصيل إضافية
--output, -o      : مسار مجلد الإخراج
```

## الملفات 📁

```
web-intel/
├── main.py              # نقطة الدخول الرئيسية
├── domain_analyzer.py   # تحليل النطاقات
├── email_analyzer.py    # تحليل البريد
├── security_checker.py  # فحص الأمان
├── breach_checker.py    # فحص الاختراقات
├── pdf_generator.py     # إنشاء تقارير PDF
├── config.py            # الإعدادات
├── requirements.txt     # المكتبات المطلوبة
├── .env.example         # مثال على متغيرات البيئة
└── reports/             # مجلد التقارير
```

## المتطلبات 📋

- Python 3.8+
- الاتصال بالإنترنت
- لا تحتاج مفاتيح API (اختيارية للميزات المتقدمة)

## ⚖️ ملاحظات قانونية

⚠️ **تحذير مهم:**
- استخدم الأداة فقط بموافقة صريحة
- احترم قوانين الخصوصية في بلدك
- لا تستخدمها للتجسس أو الأغراض غير القانونية
- المعلومات التي تجمعها عامة ومتاحة للجميع

## الترخيص 📄

Apache License 2.0

## الدعم 💬

إذا واجهت مشاكل، افتح Issue على GitHub أو تواصل معي.
