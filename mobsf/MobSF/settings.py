# noqa: E800
"""
Django settings for MobSF project.

MobSF and Django settings
"""

import logging
import os

from mobsf.MobSF.init import (
    first_run,
    get_mobsf_home,
    get_mobsf_version,
)

logger = logging.getLogger(__name__)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#       MOBSF CONFIGURATION
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
BANNER, VERSION, MOBSF_VER = get_mobsf_version()
USE_HOME = True
# True : All Uploads/Downloads will be stored in user's home directory
# False : All Uploads/Downloads will be stored under MobSF root directory

# MobSF Data Directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MobSF_HOME = get_mobsf_home(USE_HOME, BASE_DIR)
# Download Directory
DWD_DIR = os.path.join(MobSF_HOME, 'downloads/')
# Screenshot Directory
SCREEN_DIR = os.path.join(MobSF_HOME, 'downloads/screen/')
# Upload Directory
UPLD_DIR = os.path.join(MobSF_HOME, 'uploads/')
# Database Directory
DB_DIR = os.path.join(MobSF_HOME, 'db.sqlite3')
# Signatures used by modules
SIGNATURE_DIR = os.path.join(MobSF_HOME, 'signatures/')
# Tools Directory
TOOLS_DIR = os.path.join(BASE_DIR, 'DynamicAnalyzer/tools/')
# Secret File
SECRET_FILE = os.path.join(MobSF_HOME, 'secret')

# ==========MobSF User Settings==========
CONFIG_HOME = False

# ===MOBSF SECRET GENERATION AND DB MIGRATION====
SECRET_KEY = first_run(SECRET_FILE, BASE_DIR, MobSF_HOME)

# =============ALLOWED DOWNLOAD EXTENSIONS=====
ALLOWED_EXTENSIONS = {
    '.txt': 'text/plain',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.webp': 'image/webp',
    '.zip': 'application/zip',
    '.tar': 'application/x-tar',
    '.apk': 'application/octet-stream',
    '.ipa': 'application/octet-stream',
    '.jar': 'application/java-archive',
    '.aar': 'application/octet-stream',
    '.so': 'application/octet-stream',
    '.dylib': 'application/octet-stream',
    '.a': 'application/octet-stream',
    '.pcap': 'application/vnd.tcpdump.pcap',
}
# =============ALLOWED MIMETYPES=================
APK_MIME = [
    'application/octet-stream',
    'application/vnd.android.package-archive',
    'application/x-zip-compressed',
    'binary/octet-stream',
    'application/java-archive',
]
IPA_MIME = [
    'application/iphone',
    'application/octet-stream',
    'application/x-itunes-ipa',
    'application/x-zip-compressed',
    'application/x-ar',
    'text/vnd.a',
    'binary/octet-stream',
]
ZIP_MIME = [
    'application/zip',
    'application/octet-stream',
    'application/x-zip-compressed',
    'binary/octet-stream',
]
APPX_MIME = [
    'application/octet-stream',
    'application/vns.ms-appx',
    'application/x-zip-compressed',
]

# REST API only mode
# Set MOBSF_API_ONLY to 1 to enable REST API only mode
# In this mode, web UI related urls are disabled.
API_ONLY = os.getenv('MOBSF_API_ONLY', '0')

# -----External URLS--------------------------
MALWARE_DB_URL = 'https://www.malwaredomainlist.com/mdlcsv.php'
MALTRAIL_DB_URL = ('https://raw.githubusercontent.com/stamparm/aux/'
                   'master/maltrail-malware-domains.txt')
VIRUS_TOTAL_BASE_URL = 'https://www.virustotal.com/vtapi/v2/file/'
EXODUS_URL = 'https://reports.exodus-privacy.eu.org'
APPMONSTA_URL = 'https://api.appmonsta.com/v1/stores/android/details/'
ITUNES_URL = 'https://itunes.apple.com/lookup'
GITHUB_URL = ('https://github.com/MobSF/Mobile-Security-Framework-MobSF/'
              'releases/latest')
FRIDA_SERVER = 'https://api.github.com/repos/frida/frida/releases/tags/'
GOOGLE = 'https://www.google.com'
BAIDU = 'https://www.baidu.com/'
APKPURE = 'https://m.apkpure.com/android/{}/download?from=details'
APKTADA = 'https://apktada.com/download-apk/'
APKPLZ = 'https://apkplz.net/download-app/'

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# ============DJANGO SETTINGS =================
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# Database
# https://docs.djangoproject.com/en/dev/ref/settings/#databases
# Sqlite3 support

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': DB_DIR,
    },
}
# End Sqlite3 support

# Postgres DB - Install psycopg2
"""
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': os.environ['POSTGRES_DB'],
        'USER': os.environ['POSTGRES_USER'],
        'PASSWORD': os.environ['POSTGRES_PASSWORD'],
        'HOST': os.environ['POSTGRES_HOST'],
        'PORT': 5432,
    }
}
# End Postgres support
"""

# ===============================================
DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'
DEBUG = False
DJANGO_LOG_LEVEL = DEBUG
ALLOWED_HOSTS = ['127.0.0.1', 'mobsf', '*']
# Application definition
INSTALLED_APPS = (
    # 'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'mobsf.StaticAnalyzer',
    'mobsf.DynamicAnalyzer',
    'mobsf.MobSF',
    'mobsf.MalwareAnalyzer',
    'background_task',
)
MIDDLEWARE_CLASSES = (
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.contrib.auth.middleware.RemoteUserMiddleware',
)
AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.RemoteUserBackend',
)
MIDDLEWARE = (
    'mobsf.MobSF.views.api.api_middleware.RestApiAuthMiddleware',
    'mobsf.MobSF.views.aws_sso_middleware.alb_idp_auth_middleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
)
ROOT_URLCONF = 'mobsf.MobSF.urls'
WSGI_APPLICATION = 'mobsf.MobSF.wsgi.application'
LANGUAGE_CODE = 'en-us'
TIME_ZONE = os.getenv('TIME_ZONE', 'UTC')
USE_I18N = True
USE_L10N = True
USE_TZ = True
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'DIRS':
            [
                os.path.join(BASE_DIR, 'templates'),
            ],
        'OPTIONS':
            {
                'debug': True,
            },
    },
]
MEDIA_ROOT = os.path.join(BASE_DIR, 'uploads')
MEDIA_URL = '/uploads/'
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedStaticFilesStorage'
# 256MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 268435456
# Better logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'standard': {
            'format': '[%(levelname)s] %(asctime)-15s - %(message)s',
            'datefmt': '%d/%b/%Y %H:%M:%S',
        },
        'color': {
            '()': 'colorlog.ColoredFormatter',
            'format':
                '%(log_color)s[%(levelname)s] %(asctime)-15s - %(message)s',
            'datefmt': '%d/%b/%Y %H:%M:%S',
            'log_colors': {
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            },
        },
    },
    'handlers': {
        'logfile': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': os.path.join(MobSF_HOME, 'debug.log'),
            'formatter': 'standard',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'color',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'django.db.backends': {
            'handlers': ['console', 'logfile'],
            # DEBUG will log all queries, so change it to WARNING.
            'level': 'INFO',
            'propagate': False,   # Don't propagate to other handlers
        },
        'mobsf.MobSF': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'mobsf.StaticAnalyzer': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'mobsf.MalwareAnalyzer': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'mobsf.DynamicAnalyzer': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
JADX_TIMEOUT = int(os.getenv('MOBSF_JADX_TIMEOUT', 1800))
# ===========================
# ENTERPRISE FEATURE REQUESTS
# ===========================
EFR_01 = os.getenv('EFR_01', '0')
# USER CONFIGURATION
# ===================
if not CONFIG_HOME:
    """
    IMPORTANT
    If 'CONFIG_HOME' is set to True,
    then below user configuration settings are not considered.
    The user configuration will be loaded from
    .MobSF/config.py in user's home directory.
    """
    # ^CONFIG-START^: Do not edit this line
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    #          MOBSF USER CONFIGURATIONS
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # -------------------------
    # STATIC ANALYZER SETTINGS
    # -------------------------

    # ==========ANDROID SKIP CLASSES==========================
    # Common third party classes/paths that will be skipped
    # during static analysis
    import os
    SKIP_CLASS_PATH = {
        'com/google/', 'androidx', 'okhttp2/', 'okhttp3/',
        'com/android/', 'com/squareup', 'okhttp/'
        'android/content/', 'com/twitter/', 'twitter4j/',
        'android/support/', 'org/apache/', 'oauth/signpost',
        'android/arch', 'org/chromium/', 'com/facebook',
        'org/spongycastle', 'org/bouncycastle',
        'com/amazon/identity/', 'io/fabric/sdk',
        'com/instabug', 'com/crashlytics/android',
        'kotlinx/', 'kotlin/',
    }
    # Disable CVSSV2 Score by default
    CVSS_SCORE_ENABLED = bool(os.getenv('MOBSF_CVSS_SCORE_ENABLED', ''))
    # NIAP Scan
    NIAP_ENABLED = os.getenv('MOBSF_NIAP_ENABLED', '1')
    # Permission to Code Mapping
    PERM_MAPPING_ENABLED = os.getenv('MOBSF_PERM_MAPPING_ENABLED', '1')
    # Dex 2 Smali Conversion
    DEX2SMALI_ENABLED = os.getenv('MOBSF_DEX2SMALI_ENABLED', '1')
    # Android Shared Object Binary Analysis
    SO_ANALYSIS_ENABLED = os.getenv('MOBSF_SO_ANALYSIS_ENABLED', '1')
    # iOS Dynamic Library Binary Analysis
    DYLIB_ANALYSIS_ENABLED = os.getenv('MOBSF_DYLIB_ANALYSIS_ENABLED', '1')
    # =================================================
    # --------------------------
    # MALWARE ANALYZER SETTINGS
    # --------------------------

    DOMAIN_MALWARE_SCAN = os.getenv('MOBSF_DOMAIN_MALWARE_SCAN', '1')
    APKID_ENABLED = os.getenv('MOBSF_APKID_ENABLED', '1')
    QUARK_ENABLED = bool(os.getenv('MOBSF_QUARK_ENABLED', ''))
    # ==================================================
    # ======WINDOWS STATIC ANALYSIS SETTINGS ===========
    # Private key
    WINDOWS_VM_SECRET = os.getenv(
        'MOBSF_WINDOWS_VM_SECRET', 'mobsf/MobSF/windows_vm_priv_key.asc')
    # IP and Port of the MobSF Windows VM
    # example: WINDOWS_VM_IP = '127.0.0.1'   ;noqa E800
    WINDOWS_VM_IP = os.getenv('MOBSF_WINDOWS_VM_IP')
    WINDOWS_VM_PORT = os.getenv('MOBSF_WINDOWS_VM_PORT', '8000')
    # ==================================================

    # ==============3rd Party Tools=====================
    """
    If you want to use a different version of 3rd party tools used by MobSF.
    You can do that by specifying the path here. If specified, MobSF will run
    the tool from this location.
    """

    # Android 3P Tools
    JADX_BINARY = os.getenv('MOBSF_JADX_BINARY', '')
    BACKSMALI_BINARY = os.getenv('MOBSF_BACKSMALI_BINARY', '')
    VD2SVG_BINARY = os.getenv('MOBSF_VD2SVG_BINARY', '')
    APKTOOL_BINARY = os.getenv('MOBSF_APKTOOL_BINARY', '')
    ADB_BINARY = os.getenv('MOBSF_ADB_BINARY', '')

    # iOS 3P Tools
    JTOOL_BINARY = os.getenv('MOBSF_JTOOL_BINARY', '')
    CLASSDUMP_BINARY = os.getenv('MOBSF_CLASSDUMP_BINARY', '')
    CLASSDUMP_SWIFT_BINARY = os.getenv('MOBSF_CLASSDUMP_SWIFT_BINARY', '')

    # COMMON
    JAVA_DIRECTORY = os.getenv('MOBSF_JAVA_DIRECTORY', '')

    """
    Examples:
    JAVA_DIRECTORY = 'C:/Program Files/Java/jdk1.7.0_17/bin/'
    JAVA_DIRECTORY = '/usr/bin/'
    JADX_BINARY = 'C:/Users/Ajin/AppData/Local/Programs/jadx/bin/jadx.bat'
    JADX_BINARY = '/Users/ajin/jadx/bin/jadx'
    """
    # ==========================================================
    # -------------------------
    # DYNAMIC ANALYZER SETTINGS
    # -------------------------

    # =======ANDROID DYNAMIC ANALYSIS SETTINGS===========
    ANALYZER_IDENTIFIER = os.getenv('MOBSF_ANALYZER_IDENTIFIER', '')
    FRIDA_TIMEOUT = int(os.getenv('MOBSF_FRIDA_TIMEOUT', '4'))
    ACTIVITY_TESTER_SLEEP = int(os.getenv('MOBSF_ACTIVITY_TESTER_SLEEP', '4'))
    # ==============================================

    # ================HTTPS PROXY ===============
    PROXY_IP = os.getenv('MOBSF_PROXY_IP', '127.0.0.1')
    PROXY_PORT = int(os.getenv('MOBSF_PROXY_PORT', '1337'))
    # ===================================================

    # ========UPSTREAM PROXY SETTINGS ==============
    # If you are behind a Proxy
    UPSTREAM_PROXY_ENABLED = bool(os.getenv(
        'MOBSF_UPSTREAM_PROXY_ENABLED', ''))
    UPSTREAM_PROXY_SSL_VERIFY = os.getenv(
        'MOBSF_UPSTREAM_PROXY_SSL_VERIFY', '1')
    UPSTREAM_PROXY_TYPE = os.getenv('MOBSF_UPSTREAM_PROXY_TYPE', 'http')
    UPSTREAM_PROXY_IP = os.getenv('MOBSF_UPSTREAM_PROXY_IP', '127.0.0.1')
    UPSTREAM_PROXY_PORT = int(os.getenv('MOBSF_UPSTREAM_PROXY_PORT', '3128'))
    UPSTREAM_PROXY_USERNAME = os.getenv('MOBSF_UPSTREAM_PROXY_USERNAME', '')
    UPSTREAM_PROXY_PASSWORD = os.getenv('MOBSF_UPSTREAM_PROXY_PASSWORD', '')
    # ==============================================

    # ========DISABLED BY DEFAULT COMPONENTS=========
    # Get AppMonsta API from https://appmonsta.com/dashboard/get_api_key/
    APPMONSTA_API = os.getenv('MOBSF_APPMONSTA_API', '')
    # ----------VirusTotal--------------------------
    VT_ENABLED = bool(os.getenv('MOBSF_VT_ENABLED', ''))
    VT_API_KEY = os.getenv('MOBSF_VT_API_KEY', '')
    VT_UPLOAD = bool(os.getenv('MOBSF_VT_UPLOAD', ''))
    # Before setting VT_ENABLED to True,
    # Make sure VT_API_KEY is set to your VirusTotal API key
    # register at: https://www.virustotal.com/#/join-us
    # You can get your API KEY from:
    # https://www.virustotal.com/en/user/<username>/apikey/
    # Files will be uploaded to VirusTotal
    # if VT_UPLOAD is set to True.
    # ===============================================
    # =======IOS DYNAMIC ANALYSIS SETTINGS===========
    CORELLIUM_API_DOMAIN = os.getenv('MOBSF_CORELLIUM_API_DOMAIN', '')
    CORELLIUM_API_KEY = os.getenv('MOBSF_CORELLIUM_API_KEY', '')
    CORELLIUM_PROJECT_ID = os.getenv('MOBSF_CORELLIUM_PROJECT_ID', '')
    # CORELLIUM_PROJECT_ID is optional, MobSF will use any available project id
    # ===============================================
    # ^CONFIG-END^: Do not edit this line

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# ==========CYBERSPECT SETTINGS ===============
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
AWS_REGION = os.getenv('AWS_REGION', 'us-east-2')
AWS_INTAKE_LAMBDA = os.getenv('AWS_INTAKE_LAMBDA', '')
DEPENDENCY_TRACK_URL = os.getenv('DEPENDENCY_TRACK_URL')
ADMIN_USERS = os.getenv('ADMIN_USERS', 'admin@cyberspect.com')
GENERAL_GROUP = os.getenv('GENERAL_GROUP', ' ')
ADMIN_GROUP = os.getenv('ADMIN_GROUP', ' ')
TENANT_STATIC_URL = STATIC_URL + os.getenv('TENANT_ID', '')
if (not TENANT_STATIC_URL.endswith('/')):
    TENANT_STATIC_URL = TENANT_STATIC_URL + '/'
JADX_THREADS = os.getenv('JADX_THREADS', '4')
DEFAULT_PAGINATION_CLASS = 'utils.FasterPageNumberPagination'

# Customization settings
CZ100 = os.getenv('CZ100', '')
