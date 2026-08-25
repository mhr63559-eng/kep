"""
تحليل معلومات البريد الإلكتروني
"""
import re
import requests
import dns.resolver
from datetime import datetime
from config import DEFAULT_TIMEOUT, USER_AGENT


class EmailAnalyzer:
    """تحليل بيانات البريد الإلكتروني"""
    
    def __init__(self, email):
        self.email = email.lower().strip()
        self.data = {}
        self.errors = []
        self.is_valid = False
    
    def validate_email(self):
        """التحقق من صحة صيغة البريد"""
        try:
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            self.is_valid = bool(re.match(pattern, self.email))
            self.data['validation'] = {
                'is_valid': self.is_valid,
                'email': self.email if self.is_valid else 'Invalid Format'
            }
            return self.is_valid
        except Exception as e:
            self.errors.append(f"Validation Error: {str(e)}")
            self.data['validation'] = {'error': str(e)}
            return False
    
    def extract_domain(self):
        """استخراج مجال البريد"""
        try:
            domain = self.email.split('@')[1]
            self.data['domain'] = domain
            return domain
        except:
            return None
    
    def check_mx_records(self):
        """فحص سجلات MX"""
        try:
            domain = self.extract_domain()
            if not domain:
                return False
            
            mx_records = []
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_records.append({
                    'priority': rdata.preference,
                    'exchange': str(rdata.exchange).rstrip('.')
                })
            
            self.data['mx_records'] = mx_records
            return True
        except Exception as e:
            self.errors.append(f"MX Records Error: {str(e)}")
            self.data['mx_records'] = []
            return False
    
    def check_breaches(self):
        """فحص التسريبات عبر Have I Been Pwned"""
        try:
            url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{self.email}'
            headers = {'User-Agent': USER_AGENT}
            
            response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
            
            if response.status_code == 200:
                breaches = response.json()
                self.data['breaches'] = {
                    'count': len(breaches),
                    'list': [{
                        'name': b.get('Name', 'Unknown'),
                        'date': b.get('BreachDate', 'Unknown'),
                        'compromised_data': b.get('DataClasses', [])
                    } for b in breaches]
                }
            elif response.status_code == 404:
                self.data['breaches'] = {
                    'count': 0,
                    'status': '✓ لم يتم العثور على تسريبات'
                }
            else:
                self.data['breaches'] = {'status': 'Unable to check'}
            
            return True
        except Exception as e:
            self.errors.append(f"Breach Check Error: {str(e)}")
            self.data['breaches'] = {'error': str(e)}
            return False
    
    def check_paste_sites(self):
        """فحص مواقع Paste"""
        try:
            url = f'https://haveibeenpwned.com/api/v3/pasteaccount/{self.email}'
            headers = {'User-Agent': USER_AGENT}
            
            response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
            
            if response.status_code == 200:
                pastes = response.json()
                self.data['paste_sites'] = {
                    'count': len(pastes),
                    'list': [{
                        'title': p.get('Title', 'Unknown'),
                        'date': p.get('Date', 'Unknown'),
                        'source': p.get('Source', 'Unknown')
                    } for p in pastes]
                }
            elif response.status_code == 404:
                self.data['paste_sites'] = {
                    'count': 0,
                    'status': 'No pastes found'
                }
            else:
                self.data['paste_sites'] = {'status': 'Unable to check'}
            
            return True
        except Exception as e:
            self.errors.append(f"Paste Check Error: {str(e)}")
            return False
    
    def get_domain_info(self):
        """جلب معلومات مجال البريد"""
        try:
            domain = self.extract_domain()
            if not domain:
                return False
            
            # فحص A records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                self.data['domain_a_records'] = [str(rdata) for rdata in a_records]
            except:
                pass
            
            # فحص SPF
            try:
                spf = dns.resolver.resolve(domain, 'TXT')
                spf_records = [str(rdata) for rdata in spf if 'spf' in str(rdata).lower()]
                self.data['spf_records'] = spf_records if spf_records else 'No SPF'
            except:
                pass
            
            return True
        except Exception as e:
            self.errors.append(f"Domain Info Error: {str(e)}")
            return False
    
    def analyze_risk(self):
        """تحليل مستوى الخطر"""
        try:
            risk_level = 0
            risk_factors = []
            
            # فحص الصيغة
            if not self.is_valid:
                risk_level += 3
                risk_factors.append('صيغة بريد غير صحيحة')
            
            # فحص التسريبات
            if 'breaches' in self.data:
                if self.data['breaches'].get('count', 0) > 0:
                    risk_level += 3
                    risk_factors.append(f"تم العثور على {self.data['breaches']['count']} تسريب")
            
            # فحص Paste
            if 'paste_sites' in self.data:
                if self.data['paste_sites'].get('count', 0) > 0:
                    risk_level += 2
                    risk_factors.append(f"تم العثور على {self.data['paste_sites']['count']} موقع paste")
            
            # فحص MX
            if not self.data.get('mx_records'):
                risk_level += 1
                risk_factors.append('لا توجد سجلات MX صالحة')
            
            # تحديد مستوى الخطر
            if risk_level >= 6:
                risk_status = '🔴 عالي جداً'
            elif risk_level >= 4:
                risk_status = '🟠 عالي'
            elif risk_level >= 2:
                risk_status = '🟡 متوسط'
            else:
                risk_status = '🟢 منخفض'
            
            self.data['risk_assessment'] = {
                'level': risk_status,
                'score': risk_level,
                'factors': risk_factors
            }
            
            return True
        except Exception as e:
            self.errors.append(f"Risk Analysis Error: {str(e)}")
            return False
    
    def analyze(self):
        """تحليل شامل للبريد"""
        print(f"📧 جاري تحليل البريد: {self.email}")
        print("-" * 60)
        
        if not self.validate_email():
            print("✗ البريد بصيغة غير صحيحة")
            return False
        
        print("✓ تم التحقق من الصيغة")
        
        self.check_mx_records()
        print("✓ تم فحص سجلات MX")
        
        self.check_breaches()
        print("✓ تم فحص التسريبات")
        
        self.check_paste_sites()
        print("✓ تم فحص مواقع Paste")
        
        self.get_domain_info()
        print("✓ تم جلب معلومات المجال")
        
        self.analyze_risk()
        print("✓ تم تحليل مستوى الخطر")
        
        print("-" * 60)
        print("✅ اكتمل التحليل!\n")
        
        return True
    
    def get_data(self):
        """الحصول على جميع البيانات"""
        return {
            'email': self.email,
            'analysis': self.data,
            'errors': self.errors
        }
