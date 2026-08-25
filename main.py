#!/usr/bin/env python3
"""
أداة استخبارات ويب - Web Intelligence Analyzer
جمع معلومات النطاقات والبريد الإلكتروني
"""
import argparse
import sys
import json
from datetime import datetime
from domain_analyzer import DomainAnalyzer
from email_analyzer import EmailAnalyzer
from pdf_generator import PDFGenerator
from config import OUTPUT_DIR


def main():
    """الدالة الرئيسية"""
    parser = argparse.ArgumentParser(
        description="أداة استخبارات ويب - جمع معلومات النطاقات والبريد الإلكتروني",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
أمثلة الاستخدام:
  python3 main.py --domain example.com
  python3 main.py --email user@example.com
  python3 main.py --domain example.com --email user@example.com --report
  python3 main.py -d example.com -v --report
        """
    )
    
    parser.add_argument(
        '--domain', '-d',
        type=str,
        help='اسم النطاق (مثل: example.com)'
    )
    
    parser.add_argument(
        '--email', '-e',
        type=str,
        help='البريد الإلكتروني (مثل: user@example.com)'
    )
    
    parser.add_argument(
        '--report', '-r',
        action='store_true',
        help='إنشاء تقرير PDF'
    )
    
    parser.add_argument(
        '--json', '-j',
        action='store_true',
        help='حفظ البيانات بصيغة JSON'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='عرض تفاصيل إضافية'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default=OUTPUT_DIR,
        help='مسار مجلد الإخراج'
    )
    
    args = parser.parse_args()
    
    # التحقق من وجود هدف
    if not args.domain and not args.email:
        print("❌ الخطأ: يجب تحديد نطاق أو بريد إلكتروني!")
        parser.print_help()
        return 1
    
    analysis_results = {}
    
    # تحليل النطاق
    if args.domain:
        print("\n" + "="*60)
        print("🔍 تحليل النطاق")
        print("="*60 + "\n")
        
        try:
            domain_analyzer = DomainAnalyzer(args.domain)
            if domain_analyzer.analyze():
                analysis_results['domain_analysis'] = domain_analyzer.get_data()
                if args.verbose:
                    print("\n📊 البيانات المجمعة:")
                    if 'whois' in domain_analyzer.data:
                        print(f"  ✓ Whois: {domain_analyzer.data['whois'].get('domain_name', 'N/A')}")
                    if 'ip' in domain_analyzer.data:
                        print(f"  ✓ IP: {domain_analyzer.data['ip'].get('address', 'N/A')}")
        except Exception as e:
            print(f"❌ خطأ في تحليل النطاق: {e}")
    
    # تحليل البريد
    if args.email:
        print("\n" + "="*60)
        print("📧 تحليل البريد الإلكتروني")
        print("="*60 + "\n")
        
        try:
            email_analyzer = EmailAnalyzer(args.email)
            if email_analyzer.analyze():
                analysis_results['email_analysis'] = email_analyzer.get_data()
                if args.verbose:
                    if 'risk_assessment' in email_analyzer.data:
                        risk = email_analyzer.data['risk_assessment']
                        print(f"\n📊 تقييم الخطر:")
                        print(f"  • المستوى: {risk.get('level', 'N/A')}")
                        print(f"  • النقاط: {risk.get('score', 0)}/10")
        except Exception as e:
            print(f"❌ خطأ في تحليل البريد: {e}")
    
    # إنشاء التقرير
    if args.report and analysis_results:
        print("\n" + "="*60)
        print("📄 إنشاء التقرير")
        print("="*60 + "\n")
        
        try:
            target = args.domain or args.email
            generator = PDFGenerator(target)
            if generator.generate(analysis_results):
                print(f"📁 المسار: {generator.filepath}")
        except Exception as e:
            print(f"❌ خطأ في إنشاء التقرير: {e}")
    
    # حفظ JSON
    if args.json and analysis_results:
        try:
            json_file = f"{OUTPUT_DIR}/analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(analysis_results, f, ensure_ascii=False, indent=2)
            print(f"✓ تم حفظ JSON: {json_file}")
        except Exception as e:
            print(f"❌ خطأ في حفظ JSON: {e}")
    
    print("\n" + "="*60)
    print("✅ اكتمل التحليل!")
    print("="*60 + "\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
