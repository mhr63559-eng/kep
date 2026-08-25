"""
تحليل معلومات النطاقات
"""
import whois
import socket
import dns.resolver
import ssl
import requests
from datetime import datetime
from urllib.parse import urlparse
from config import DEFAULT_TIMEOUT, USER_AGENT, MAX_RETRIES


class DomainAnalyzer:
    """تحليل بيانات النطاق"""
    
    def __init__(self, domain):
        self.domain = domain.replace('www.', '').strip()
        self.data = {}
        self.errors = []
    
    def get_whois_info(self):
        """جلب بيانات Whois"""
        try:
            w = whois.whois(self.domain)
            self.data['whois'] = {
                'domain_name': str(w.domain_name) if w.domain_name else self.domain,
                'registrar': str(w.registrar) if w.registrar else 'Unknown',
                'creation_date': str(w.creation_date) if w.creation_date else 'Unknown',
                'expiration_date': str(w.expiration_date) if w.expiration_date else 'Unknown',
                'updated_date': str(w.updated_date) if w.updated_date else 'Unknown',
                'name_servers': w.name_servers if w.name_servers else [],
                'registrant_name': str(w.registrant_name) if hasattr(w, 'registrant_name') and w.registrant_name else 'Private',
                'registrant_country': str(w.registrant_country) if hasattr(w, 'registrant_country') and w.registrant_country else 'Unknown',
            }
            return True
        except Exception as e:
            self.errors.append(f"Whois Error: {str(e)}")
            self.data['whois'] = {'error': str(e)}
            return False
    
    def get_ip_info(self):
        """جلب معلومات IP والموقع"""
        try:
            ip = socket.gethostbyname(self.domain)
            self.data['ip'] = {
                'address': ip,
                'timestamp': datetime.now().isoformat()
            }
            
            # محاولة الحصول على معلومات الموقع
            try:
                response = requests.get(
                    f'https://ipapi.co/{ip}/json/',
                    timeout=DEFAULT_TIMEOUT
                )
                if response.status_code == 200:
                    geo = response.json()
                    self.data['ip']['location'] = {
                        'city': geo.get('city', 'Unknown'),
                        'country': geo.get('country_name', 'Unknown'),
                        'country_code': geo.get('country_code', 'Unknown'),
                        'latitude': geo.get('latitude', 0),
                        'longitude': geo.get('longitude', 0),
                        'timezone': geo.get('timezone', 'Unknown'),
                        'isp': geo.get('org', 'Unknown')
                    }
            except:
                pass
            
            return True
        except Exception as e:
            self.errors.append(f"IP Lookup Error: {str(e)}")
            self.data['ip'] = {'error': str(e)}
            return False
    
    def get_dns_records(self):
        """جلب سجلات DNS"""
        try:
            dns_records = {}
            record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    dns_records[record_type] = [str(rdata) for rdata in answers]
                except:
                    pass
            
            self.data['dns'] = dns_records if dns_records else {'status': 'No records found'}
            return True
        except Exception as e:
            self.errors.append(f"DNS Error: {str(e)}")
            self.data['dns'] = {'error': str(e)}
            return False
    
    def get_ssl_certificate(self):
        """جلب معلومات شهادة SSL"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=DEFAULT_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    self.data['ssl'] = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'subjectAltName': [x[1] for x in cert.get('subjectAltName', [])]
                    }
                    return True
        except Exception as e:
            self.errors.append(f"SSL Certificate Error: {str(e)}")
            self.data['ssl'] = {'error': 'No SSL Certificate or Certificate Error'}
            return False
    
    def get_http_headers(self):
        """جلب رؤوس HTTP"""
        try:
            url = f'https://{self.domain}'
            response = requests.head(
                url,
                timeout=DEFAULT_TIMEOUT,
                headers={'User-Agent': USER_AGENT},
                allow_redirects=True
            )
            self.data['http'] = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'response_time': response.elapsed.total_seconds()
            }
            return True
        except:
            try:
                url = f'http://{self.domain}'
                response = requests.head(
                    url,
                    timeout=DEFAULT_TIMEOUT,
                    headers={'User-Agent': USER_AGENT}
                )
                self.data['http'] = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'response_time': response.elapsed.total_seconds(),
                    'protocol': 'HTTP (not HTTPS)'
                }
                return True
            except Exception as e:
                self.errors.append(f"HTTP Headers Error: {str(e)}")
                self.data['http'] = {'error': str(e)}
                return False
    
    def check_security(self):
        """فحص الأمان الأساسي"""
        try:
            security_status = {
                'https': False,
                'ssl_valid': False,
                'security_headers': []
            }
            
            # فحص HTTPS
            try:
                response = requests.get(
                    f'https://{self.domain}',
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=False
                )
                security_status['https'] = True
            except:
                pass
            
            # فحص رؤوس الأمان
            if 'http' in self.data and 'headers' in self.data['http']:
                headers = self.data['http']['headers']
                security_headers = [
                    'Strict-Transport-Security',
                    'X-Content-Type-Options',
                    'X-Frame-Options',
                    'X-XSS-Protection',
                    'Content-Security-Policy'
                ]
                security_status['security_headers'] = [
                    h for h in security_headers if h in headers
                ]
            
            if 'ssl' in self.data and 'error' not in self.data['ssl']:
                security_status['ssl_valid'] = True
            
            self.data['security'] = security_status
            return True
        except Exception as e:
            self.errors.append(f"Security Check Error: {str(e)}")
            return False
    
    def analyze(self):
        """تحليل شامل للنطاق"""
        print(f"🔍 جاري تحليل النطاق: {self.domain}")
        print("-" * 60)
        
        self.get_whois_info()
        print("✓ تم جلب بيانات Whois")
        
        self.get_ip_info()
        print("✓ تم جلب معلومات IP")
        
        self.get_dns_records()
        print("✓ تم جلب سجلات DNS")
        
        self.get_ssl_certificate()
        print("✓ تم جلب بيانات SSL")
        
        self.get_http_headers()
        print("✓ تم جلب رؤوس HTTP")
        
        self.check_security()
        print("✓ تم فحص الأمان")
        
        print("-" * 60)
        print("✅ اكتمل التحليل!\n")
        
        return True
    
    def get_data(self):
        """الحصول على جميع البيانات"""
        return {
            'domain': self.domain,
            'analysis': self.data,
            'errors': self.errors
        }
