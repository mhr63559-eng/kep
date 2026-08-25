"""
إنشاء تقارير PDF احترافية
"""
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
from datetime import datetime
import os
from config import OUTPUT_DIR


class PDFGenerator:
    """إنشاء تقارير PDF احترافية"""
    
    def __init__(self, target_name):
        self.target_name = target_name.replace('@', '_').replace('.', '_')
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = f"intelligence_report_{self.target_name}_{self.timestamp}.pdf"
        self.filepath = os.path.join(OUTPUT_DIR, self.filename)
    
    def generate(self, analysis_data):
        """توليد التقرير"""
        try:
            doc = SimpleDocTemplate(
                self.filepath,
                pagesize=A4,
                rightMargin=0.75*inch,
                leftMargin=0.75*inch,
                topMargin=0.75*inch,
                bottomMargin=0.75*inch
            )
            
            elements = []
            styles = getSampleStyleSheet()
            
            # الصفحة الأولى
            elements.extend(self._create_title_page(analysis_data, styles))
            elements.append(PageBreak())
            
            # معلومات النطاق
            if 'domain_analysis' in analysis_data:
                elements.extend(self._create_domain_page(analysis_data['domain_analysis'], styles))
                elements.append(PageBreak())
            
            # معلومات البريد
            if 'email_analysis' in analysis_data:
                elements.extend(self._create_email_page(analysis_data['email_analysis'], styles))
                elements.append(PageBreak())
            
            # الملخص النهائي
            elements.extend(self._create_summary_page(analysis_data, styles))
            
            # بناء الوثيقة
            doc.build(elements)
            
            print(f"✅ تم إنشاء التقرير: {self.filepath}")
            return True
            
        except Exception as e:
            print(f"❌ خطأ في إنشاء التقرير: {e}")
            return False
    
    def _create_title_page(self, data, styles):
        """إنشاء الصفحة الأولى"""
        elements = []
        
        # العنوان الرئيسي
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=32,
            textColor=colors.HexColor('#1E90FF'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        elements.append(Spacer(1, 1*inch))
        elements.append(Paragraph("تقرير استخبارات ويب 🔍", title_style))
        elements.append(Paragraph("Web Intelligence Report", title_style))
        
        # تاريخ التقرير
        date_style = ParagraphStyle(
            'DateStyle',
            parent=styles['Normal'],
            fontSize=14,
            alignment=TA_CENTER,
            spaceAfter=20
        )
        elements.append(Paragraph(
            f"تاريخ التقرير: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            date_style
        ))
        
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_domain_page(self, domain_data, styles):
        """إنشاء صفحة معلومات النطاق"""
        elements = []
        elements.append(Paragraph("معلومات النطاق 🌐", styles['Heading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        analysis = domain_data.get('analysis', {})
        
        # Whois Information
        if 'whois' in analysis and 'error' not in analysis['whois']:
            elements.append(Paragraph("بيانات Whois:", styles['Heading3']))
            whois_data = analysis['whois']
            whois_table_data = [
                ["المعلومة", "القيمة"],
                ["النطاق", whois_data.get('domain_name', 'N/A')],
                ["المسجل", whois_data.get('registrar', 'N/A')],
                ["تاريخ الإنشاء", str(whois_data.get('creation_date', 'N/A'))],
                ["تاريخ الانتهاء", str(whois_data.get('expiration_date', 'N/A'))],
            ]
            table = Table(whois_table_data, colWidths=[2*inch, 4*inch])
            table.setStyle(self._get_table_style())
            elements.append(table)
            elements.append(Spacer(1, 0.2*inch))
        
        # IP Information
        if 'ip' in analysis and 'error' not in analysis['ip']:
            elements.append(Paragraph("معلومات IP:", styles['Heading3']))
            ip_data = analysis['ip']
            ip_table_data = [["المعلومة", "القيمة"]]
            ip_table_data.append(["عنوان IP", ip_data.get('address', 'N/A')])
            if 'location' in ip_data:
                loc = ip_data['location']
                ip_table_data.append(["المدينة", loc.get('city', 'N/A')])
                ip_table_data.append(["الدولة", loc.get('country', 'N/A')])
                ip_table_data.append(["ISP", loc.get('isp', 'N/A')])
            table = Table(ip_table_data, colWidths=[2*inch, 4*inch])
            table.setStyle(self._get_table_style())
            elements.append(table)
            elements.append(Spacer(1, 0.2*inch))
        
        # Security Status
        if 'security' in analysis:
            elements.append(Paragraph("حالة الأمان:", styles['Heading3']))
            sec = analysis['security']
            security_text = f"HTTPS: {'✓' if sec.get('https') else '✗'} | SSL: {'✓' if sec.get('ssl_valid') else '✗'}"
            elements.append(Paragraph(security_text, styles['Normal']))
            elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _create_email_page(self, email_data, styles):
        """إنشاء صفحة معلومات البريد"""
        elements = []
        elements.append(Paragraph("معلومات البريد الإلكتروني 📧", styles['Heading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        analysis = email_data.get('analysis', {})
        
        # Validation
        if 'validation' in analysis:
            val = analysis['validation']
            status = "✓ صحيح" if val.get('is_valid') else "✗ غير صحيح"
            elements.append(Paragraph(f"حالة البريد: {status}", styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
        
        # Risk Assessment
        if 'risk_assessment' in analysis:
            elements.append(Paragraph("تقييم الخطر:", styles['Heading3']))
            risk = analysis['risk_assessment']
            risk_table = [
                ["المستوى", risk.get('level', 'N/A')],
                ["النقاط", str(risk.get('score', 0))]
            ]
            table = Table(risk_table, colWidths=[2*inch, 4*inch])
            table.setStyle(self._get_table_style())
            elements.append(table)
            elements.append(Spacer(1, 0.2*inch))
        
        # Breaches
        if 'breaches' in analysis:
            elements.append(Paragraph("فحص التسريبات:", styles['Heading3']))
            breaches = analysis['breaches']
            if 'count' in breaches and breaches['count'] > 0:
                breach_text = f"⚠️ تم العثور على {breaches['count']} تسريب"
            else:
                breach_text = "✓ لم يتم العثور على تسريبات"
            elements.append(Paragraph(breach_text, styles['Normal']))
            elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _create_summary_page(self, data, styles):
        """إنشاء صفحة الملخص"""
        elements = []
        elements.append(Paragraph("الملخص النهائي 📋", styles['Heading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        summary = [
            ["العنصر", "الحالة"],
        ]
        
        # النطاق
        if 'domain_analysis' in data:
            summary.append(["تحليل النطاق", "✓ اكتمل"])
        
        # البريد
        if 'email_analysis' in data:
            summary.append(["تحليل البريد", "✓ اكتمل"])
        
        summary.append(["تاريخ التقرير", datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        
        table = Table(summary, colWidths=[2.5*inch, 3.5*inch])
        table.setStyle(self._get_table_style())
        elements.append(table)
        
        elements.append(Spacer(1, 0.5*inch))
        elements.append(Paragraph(
            "تنبيه: هذا التقرير يحتوي على معلومات عامة متاحة للجميع. استخدمه بمسؤولية.",
            styles['Normal']
        ))
        
        return elements
    
    def _get_table_style(self):
        """الحصول على نمط الجداول"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E90FF')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ])
