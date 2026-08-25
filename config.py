"""
تكوينات الأداة
"""
import os
from dotenv import load_dotenv

load_dotenv()

# Output Configuration
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "reports")
JSON_OUTPUT = os.getenv("JSON_OUTPUT", "True") == "True"
CSV_OUTPUT = os.getenv("CSV_OUTPUT", "True") == "True"
PDF_OUTPUT = os.getenv("PDF_OUTPUT", "True") == "True"

# API Configuration (Optional)
HAVEIBEENPWNED_KEY = os.getenv("HAVEIBEENPWNED_KEY", "")
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY", "")

# Report Configuration
REPORT_TITLE = "Web Intelligence Report"
REPORT_TITLE_AR = "تقرير استخبارات ويب"
LANGUAGE = "ar"  # en or ar

# Timeout Configuration
DEFAULT_TIMEOUT = 10
MAX_RETRIES = 3

# User Agent
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Create output directory
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = os.path.join(OUTPUT_DIR, "intelligence.log")
