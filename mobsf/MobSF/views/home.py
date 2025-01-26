# -*- coding: utf_8 -*-
"""MobSF File Upload and Home Routes."""
import datetime
import json
import logging
import os
import platform
import re
import shutil
import traceback as tb
from pathlib import Path
from datetime import timedelta
from wsgiref.util import FileWrapper

import boto3

from django.conf import settings
from django.utils.timezone import now
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.shortcuts import (
    redirect,
    render,
)
from django.template.defaulttags import register
from django.forms.models import model_to_dict
from django.views.decorators.http import require_http_methods

from mobsf.MobSF.forms import FormUtil, UploadFileForm
from mobsf.MobSF.utils import (
    MD5_REGEX,
    get_md5,
    get_siphash,
    is_admin,
    is_dir_exists,
    is_file_exists,
    is_md5,
    is_safe_path,
    key,
    print_n_send_error_response,
    python_dict,
    sso_email,
    tz,
    utcnow,
)
from mobsf.MobSF.init import api_key
from mobsf.MobSF.security import sanitize_filename
from mobsf.MobSF.views.helpers import FileType
from mobsf.MobSF.views.scanning import Scanning
from mobsf.MobSF.views.apk_downloader import apk_download
from mobsf.StaticAnalyzer.models import (
    CyberspectScans,
    EnqueuedTask,
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
    StaticAnalyzerWindows,
)
from mobsf.DynamicAnalyzer.views.common.shared import (
    invalid_params,
    send_response,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    MAINTAINER_GROUP,
    Permissions,
    permission_required,
)

LINUX_PLATFORM = ['Darwin', 'Linux']
HTTP_BAD_REQUEST = 400
HTTP_STATUS_404 = 404
HTTP_SERVER_ERROR = 500
logger = logging.getLogger(__name__)
register.filter('key', key)


@login_required
def index(request):
    """Index Route."""
    mimes = (settings.APK_MIME
             + settings.IPA_MIME
             + settings.ZIP_MIME
             + settings.APPX_MIME)
    exts = (settings.ANDROID_EXTS
            + settings.IOS_EXTS
            + settings.WINDOWS_EXTS)
    context = {
        'title': 'Cyberspect: Upload App',
        'version': settings.MOBSF_VER,
        'mimes': mimes,
        'exts': '|'.join(exts),
        'is_admin': is_admin(request),
        'email': sso_email(request),
        'tenant_static': settings.TENANT_STATIC_URL,
    }
    template = 'general/home2.html'
    return render(request, template, context)


class Upload(object):
    """Handle File Upload based on App type."""

    def __init__(self, request):
        self.request = request
        self.form = UploadFileForm(request.POST, request.FILES)
        self.scan = Scanning(self.request)

    @staticmethod
    @login_required
    @permission_required(Permissions.SCAN)
    def as_view(request):
        upload = Upload(request)
        return upload.upload_html()

    def resp_json(self, data):
        resp = HttpResponse(json.dumps(data),
                            content_type='application/json; charset=utf-8')
        return resp

    def upload_html(self):
        logger.info('File uploaded via web UI by user %s',
                    sso_email(self.request))
        try:
            request = self.request
            response_data = {
                'description': '',
                'status': 'error',
            }
            if request.method != 'POST':
                msg = 'Method not Supported!'
                logger.error(msg)
                response_data['description'] = msg
                return self.resp_json(response_data)

            if not self.form.is_valid():
                msg = 'Invalid Form Data!'
                logger.error(msg)
                response_data['description'] = msg
                return self.resp_json(response_data)

            if not self.scan.file_type.is_allow_file():
                msg = 'File format not supported: ' \
                    + self.scan.file.content_type
                logger.error(msg)
                response_data['description'] = msg
                return self.resp_json(response_data)

            if self.scan.file_type.is_ipa():
                if platform.system() not in LINUX_PLATFORM:
                    msg = 'Static Analysis of iOS IPA requires Mac or Linux'
                    logger.error(msg)
                    response_data['description'] = msg
                    return self.resp_json(response_data)

            start_time = utcnow()
            response_data = self.upload()
            self.scan.cyberspect_scan_id = \
                new_cyberspect_scan(False, response_data['hash'],
                                    start_time,
                                    self.scan.file_size,
                                    self.scan.source_file_size,
                                    sso_email(self.request))
            cyberspect_scan_intake(self.scan.populate_data_dict())
            return self.resp_json(response_data)
        except Exception as exp:
            exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
            logger.error(exmsg)
            msg = str(exp)
            exp_doc = exp.__doc__
            self.track_failure(msg)
            return print_n_send_error_response(request, msg, True, exp_doc)

    def upload_api(self):
        """API File Upload."""
        logger.info('Uploading through API')
        api_response = {}
        if not self.form.is_valid():
            api_response['error'] = FormUtil.errors_message(self.form)
            return api_response, HTTP_BAD_REQUEST
        if not self.scan.email:
            api_response['error'] = 'User email address not set'
            return api_response, HTTP_BAD_REQUEST
        if not self.scan.file_type.is_allow_file():
            api_response['error'] = 'File format not supported!'
            return api_response, HTTP_BAD_REQUEST
        start_time = utcnow()
        api_response = self.upload()
        self.scan.cyberspect_scan_id = \
            new_cyberspect_scan(False, api_response['hash'],
                                start_time,
                                self.scan.file_size,
                                self.scan.source_file_size,
                                sso_email(self.request))
        api_response['cyberspect_scan_id'] = self.scan.cyberspect_scan_id
        cyberspect_scan_intake(self.scan.populate_data_dict())
        return api_response, 200

    def upload(self):
        self.scan.rescan = '0'
        content_type = self.scan.file.content_type
        file_name = sanitize_filename(self.scan.file.name)
        logger.info('MIME Type: %s FILE: %s', content_type, file_name)
        if self.scan.file_type.is_apk():
            return self.scan.scan_apk()
        elif self.scan.file_type.is_xapk():
            return self.scan.scan_xapk()
        elif self.scan.file_type.is_apks():
            return self.scan.scan_apks()
        elif self.scan.file_type.is_aab():
            return self.scan.scan_aab()
        elif self.scan.file_type.is_jar():
            return self.scan.scan_jar()
        elif self.scan.file_type.is_aar():
            return self.scan.scan_aar()
        elif self.scan.file_type.is_so():
            return self.scan.scan_so()
        elif self.scan.file_type.is_jar():
            return self.scan.scan_jar()
        elif self.scan.file_type.is_aar():
            return self.scan.scan_aar()
        elif self.scan.file_type.is_so():
            return self.scan.scan_so()
        elif self.scan.file_type.is_zip():
            return self.scan.scan_zip()
        elif self.scan.file_type.is_ipa():
            return self.scan.scan_ipa()
        elif self.scan.file_type.is_dylib():
            return self.scan.scan_dylib()
        elif self.scan.file_type.is_a():
            return self.scan.scan_a()
        elif self.scan.file_type.is_dylib():
            return self.scan.scan_dylib()
        elif self.scan.file_type.is_a():
            return self.scan.scan_a()
        elif self.scan.file_type.is_appx():
            return self.scan.scan_appx()

    def track_failure(self, error_message):
        if self.scan.cyberspect_scan_id == 0:
            return
        data = {
            'id': self.scan.cyberspect_scan_id,
            'success': False,
            'failure_source': 'SAST',
            'failure_message': error_message,
            'sast_end': utcnow(),
        }
        update_cyberspect_scan(data)


@login_required
def api_docs(request):
    """Api Docs Route."""
    key = '*******'
    try:
        if (settings.DISABLE_AUTHENTICATION == '1'
                or request.user.is_staff
                or request.user.groups.filter(name=MAINTAINER_GROUP).exists()):
            key = api_key(settings.MOBSF_HOME)
    except Exception:
        logger.exception('[ERROR] Failed to get API key')
    if (not is_admin(request)):
        return print_n_send_error_response(request, 'Unauthorized')

    context = {
        'title': 'API Docs',
        'api_key': key,
        'version': settings.MOBSF_VER,
        'is_admin': True,
    }
    template = 'general/apidocs.html'
    return render(request, template, context)


def support(request):
    """Support Route."""
    context = {
        'title': 'Support',
        'version': settings.MOBSF_VER,
        'is_admin': is_admin(request),
        'tenant_static': settings.TENANT_STATIC_URL,
    }
    template = 'general/support.html'
    return render(request, template, context)


def about(request):
    """About Route."""
    context = {
        'title': 'About',
        'version': settings.MOBSF_VER,
        'is_admin': is_admin(request),
    }
    template = 'general/about.html'
    return render(request, template, context)


def donate(request):
    """Donate Route."""
    context = {
        'title': 'Donate',
        'version': settings.MOBSF_VER,
    }
    template = 'general/donate.html'
    return render(request, template, context)


def error(request):
    """Error Route."""
    context = {
        'title': 'Error',
        'version': settings.MOBSF_VER,
        'is_admin': is_admin(request),
    }
    template = 'general/error.html'
    return render(request, template, context)


def zip_format(request):
    """Zip Format Message Route."""
    context = {
        'title': 'Zipped Source Instruction',
        'version': settings.MOBSF_VER,
        'is_admin': is_admin(request),
    }
    template = 'general/zip.html'
    return render(request, template, context)


def not_found(request):
    """Not Found Route."""
    context = {
        'title': 'Dynamic Analysis',
        'version': settings.MOBSF_VER,
    }
    template = 'general/dynamic.html'
    return render(request, template, context)


@login_required
def recent_scans(request, page_size=10, page_number=1):
    """Show Recent Scans Route."""
    entries = []
    query = RecentScansDB.objects.all().order_by('-TIMESTAMP')
    isadmin = is_admin(request)
    if (not isadmin):
        email_filter = sso_email(request)
        if (not email_filter):
            email_filter = '@@'
        query = query.filter(EMAIL__contains=email_filter)
    paginator = Paginator(query.values(), page_size)
    page_obj = paginator.get_page(page_number)
    page_obj.page_size = page_size
    md5_list = [i['MD5'] for i in page_obj]

    android = StaticAnalyzerAndroid.objects.filter(
        MD5__in=md5_list).only(
            'PACKAGE_NAME', 'VERSION_NAME', 'FILE_NAME', 'MD5')
    ios = StaticAnalyzerIOS.objects.filter(
        MD5__in=md5_list).only('FILE_NAME', 'MD5')

    updir = Path(settings.UPLD_DIR)
    icon_mapping = {}
    package_mapping = {}
    for item in android:
        package_mapping[item.MD5] = item.PACKAGE_NAME
        icon_mapping[item.MD5] = item.ICON_PATH
    for item in ios:
        icon_mapping[item.MD5] = item.ICON_PATH

    for entry in page_obj:
        if entry['MD5'] in package_mapping.keys():
            entry['PACKAGE'] = package_mapping[entry['MD5']]
        else:
            entry['PACKAGE'] = ''
        entry['ICON_PATH'] = icon_mapping.get(entry['MD5'], '')
        if entry['FILE_NAME'].endswith('.ipa'):
            entry['BUNDLE_HASH'] = get_md5(
                entry['PACKAGE_NAME'].encode('utf-8'))
            report_file = updir / entry['BUNDLE_HASH'] / 'mobsf_dump_file.txt'
        else:
            report_file = updir / entry['MD5'] / 'logcat.txt'
        entry['DYNAMIC_REPORT_EXISTS'] = report_file.exists()
        entry['CAN_RELEASE'] = (utcnow()
                                < entry['TIMESTAMP']
                                + datetime.timedelta(days=30))
        item = CyberspectScans.objects.filter(MOBSF_MD5=entry['MD5']).last()
        if item:
            entry['DT_PROJECT_ID'] = item.DT_PROJECT_ID
            entry['COMPLETE'] = item.SAST_END
            if (item.FAILURE_SOURCE == 'SAST'):
                entry['ERROR'] = item.FAILURE_MESSAGE
            else:
                entry['ERROR'] = None
        else:
            entry['DT_PROJECT_ID'] = None
            entry['COMPLETE'] = entry['TIMESTAMP']
            entry['ERROR'] = 'Unable to find cyberspect_scans record'
        entries.append(entry)
    context = {
        'title': 'Scanned Apps',
        'entries': entries,
        'version': settings.MOBSF_VER,
        'page_obj': page_obj,
        'async_scans': settings.ASYNC_ANALYSIS,
        'is_admin': isadmin,
        'dependency_track_url': settings.DEPENDENCY_TRACK_URL,
        'filter': filter,
        'tenant_static': settings.TENANT_STATIC_URL,
    }
    template = 'general/recent.html'
    return render(request, template, context)


def scan_metadata(md5):
    """Get scan metadata."""
    if re.match('[0-9a-f]{32}', md5):
        db_obj = RecentScansDB.objects.filter(MD5=md5).first()
        if db_obj:
            return model_to_dict(db_obj)
    return None


def get_cyberspect_scan(csid):
    db_obj = CyberspectScans.objects.filter(ID=csid).first()
    if db_obj:
        cs_obj = model_to_dict(db_obj)
        return cs_obj
    return None


def new_cyberspect_scan(scheduled, md5, start_time,
                        file_size, source_file_size, sso_user):
    # Insert new record into CyberspectScans
    new_db_obj = CyberspectScans(
        SCHEDULED=scheduled,
        MOBSF_MD5=md5,
        INTAKE_START=start_time,
        FILE_SIZE_PACKAGE=file_size,
        FILE_SIZE_SOURCE=source_file_size,
        EMAIL=sso_user,
    )
    new_db_obj.save()
    logger.info('Hash: %s, Cyberspect Scan ID: %s', md5, new_db_obj.ID)
    return new_db_obj.ID


def update_scan(request, api=False):
    """Update RecentScansDB record."""
    try:
        if (not is_admin(request) and not api):
            return HttpResponse(status=403)
        md5 = request.POST['hash']
        response = {'error': f'Scan {md5} not found'}
        db_obj = RecentScansDB.objects.filter(MD5=md5).first()
        if db_obj:
            if 'user_app_name' in request.POST:
                db_obj.USER_APP_NAME = request.POST['user_app_name']
            if 'user_app_version' in request.POST:
                db_obj.USER_APP_VERSION = request.POST['user_app_version']
            if 'division' in request.POST:
                db_obj.DIVISION = request.POST['division']
            if 'environment' in request.POST:
                db_obj.ENVIRONMENT = request.POST['environment']
            if 'country' in request.POST:
                db_obj.COUNTRY = request.POST['country']
            if 'data_privacy_classification' in request.POST:
                dpc = request.POST['data_privacy_classification']
                db_obj.DATA_PRIVACY_CLASSIFICATION = dpc
            if 'data_privacy_attributes' in request.POST:
                dpa = request.POST['data_privacy_attributes']
                db_obj.DATA_PRIVACY_ATTRIBUTES = dpa
            if 'email' in request.POST:
                db_obj.EMAIL = request.POST['email']
            if 'release' in request.POST:
                db_obj.RELEASE = request.POST['release']
            db_obj.TIMESTAMP = utcnow()
            db_obj.save()
            response = model_to_dict(db_obj)
            data = {'result': 'success'}
        if api:
            return response
        else:
            ctype = 'application/json; charset=utf-8'
            return HttpResponse(json.dumps(data), content_type=ctype)
    except Exception as exp:
        exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
        logger.error(exmsg)
        msg = str(exp)
        exp_doc = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp_doc)
        else:
            return print_n_send_error_response(request, msg, False, exp_doc)


def update_cyberspect_scan(data):
    """Update Cyberspect scan record."""
    try:
        if (('id' not in data) and ('dt_project_id' in data)):
            db_obj = CyberspectScans.objects \
                .filter(DT_PROJECT_ID=data['dt_project_id']) \
                .order_by('-ID').first()
            csid = data['dt_project_id']
        else:
            db_obj = CyberspectScans.objects.filter(ID=data['id']).first()
            csid = data['id']

        if db_obj:
            if 'mobsf_md5' in data:
                db_obj.MOBSF_MD5 = data['mobsf_md5']
            if 'dt_project_id' in data and data['dt_project_id']:
                db_obj.DT_PROJECT_ID = data['dt_project_id']
            if 'intake_end' in data and data['intake_end']:
                db_obj.INTAKE_END = tz(data['intake_end'])
            if 'sast_start' in data and data['sast_start']:
                db_obj.SAST_START = tz(data['sast_start'])
            if 'sast_end' in data and data['sast_end']:
                db_obj.SAST_END = tz(data['sast_end'])
            if 'sbom_start' in data and data['sbom_start']:
                db_obj.SBOM_START = tz(data['sbom_start'])
            if 'sbom_end' in data and data['sbom_end']:
                db_obj.SBOM_END = tz(data['sbom_end'])
            if 'dependency_start' in data and data['dependency_start']:
                db_obj.DEPENDENCY_START = tz(data['dependency_start'])
            if 'dependency_end' in data and data['dependency_end']:
                db_obj.DEPENDENCY_END = tz(data['dependency_end'])
            if 'notification_start' in data and data['notification_start']:
                db_obj.NOTIFICATION_START = tz(data['notification_start'])
            if 'notification_end' in data and data['notification_end']:
                db_obj.NOTIFICATION_END = tz(data['notification_end'])
            if 'success' in data:
                db_obj.SUCCESS = data['success']
            if 'failure_source' in data and data['failure_source']:
                db_obj.FAILURE_SOURCE = data['failure_source']
            if 'failure_message' in data and data['failure_message']:
                db_obj.FAILURE_MESSAGE = data['failure_message']
            if 'file_size_package' in data and data['file_size_package']:
                db_obj.FILE_SIZE_PACKAGE = data['file_size_package']
            if 'file_size_source' in data and data['file_size_source']:
                db_obj.FILE_SIZE_SOURCE = data['file_size_source']
            if 'dependency_types' in data:
                db_obj.DEPENDENCY_TYPES = data['dependency_types']
            db_obj.save()
            return model_to_dict(db_obj)
        else:
            return {'error': f'Scan ID {csid} not found'}
    except Exception as ex:
        exmsg = ''.join(tb.format_exception(None, ex, ex.__traceback__))
        logger.error(exmsg)
        return {'error': str(ex)}


def logout_aws(request):
    """Remove AWS ALB session cookie."""
    resp = HttpResponse(
        '{}',
        content_type='application/json; charset=utf-8')
    for cookie in request.COOKIES:
        resp.set_cookie(cookie, None, -1, -1)
    return resp


def scan_metadata(md5):
    """Get scan metadata."""
    if re.match('[0-9a-f]{32}', md5):
        db_obj = RecentScansDB.objects.filter(MD5=md5).first()
        if db_obj:
            return model_to_dict(db_obj)
    return None


def get_cyberspect_scan(csid):
    db_obj = CyberspectScans.objects.filter(ID=csid).first()
    if db_obj:
        cs_obj = model_to_dict(db_obj)
        return cs_obj
    return None


def new_cyberspect_scan(scheduled, md5, start_time,
                        file_size, source_file_size, sso_user):
    # Insert new record into CyberspectScans
    new_db_obj = CyberspectScans(
        SCHEDULED=scheduled,
        MOBSF_MD5=md5,
        INTAKE_START=start_time,
        FILE_SIZE_PACKAGE=file_size,
        FILE_SIZE_SOURCE=source_file_size,
        EMAIL=sso_user,
    )
    new_db_obj.save()
    logger.info('Hash: %s, Cyberspect Scan ID: %s', md5, new_db_obj.ID)
    return new_db_obj.ID


def update_scan(request, api=False):
    """Update RecentScansDB record."""
    try:
        if (not is_admin(request) and not api):
            return HttpResponse(status=403)
        md5 = request.POST['hash']
        response = {'error': f'Scan {md5} not found'}
        db_obj = RecentScansDB.objects.filter(MD5=md5).first()
        if db_obj:
            if 'user_app_name' in request.POST:
                db_obj.USER_APP_NAME = request.POST['user_app_name']
            if 'user_app_version' in request.POST:
                db_obj.USER_APP_VERSION = request.POST['user_app_version']
            if 'division' in request.POST:
                db_obj.DIVISION = request.POST['division']
            if 'environment' in request.POST:
                db_obj.ENVIRONMENT = request.POST['environment']
            if 'country' in request.POST:
                db_obj.COUNTRY = request.POST['country']
            if 'data_privacy_classification' in request.POST:
                dpc = request.POST['data_privacy_classification']
                db_obj.DATA_PRIVACY_CLASSIFICATION = dpc
            if 'data_privacy_attributes' in request.POST:
                dpa = request.POST['data_privacy_attributes']
                db_obj.DATA_PRIVACY_ATTRIBUTES = dpa
            if 'email' in request.POST:
                db_obj.EMAIL = request.POST['email']
            if 'release' in request.POST:
                db_obj.RELEASE = request.POST['release']
            db_obj.TIMESTAMP = utcnow()
            db_obj.save()
            response = model_to_dict(db_obj)
            data = {'result': 'success'}
        if api:
            return response
        else:
            ctype = 'application/json; charset=utf-8'
            return HttpResponse(json.dumps(data), content_type=ctype)
    except Exception as exp:
        exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
        logger.error(exmsg)
        msg = str(exp)
        exp_doc = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp_doc)
        else:
            return print_n_send_error_response(request, msg, False, exp_doc)


def update_cyberspect_scan(data):
    """Update Cyberspect scan record."""
    try:
        if (('id' not in data) and ('dt_project_id' in data)):
            db_obj = CyberspectScans.objects \
                .filter(DT_PROJECT_ID=data['dt_project_id']) \
                .order_by('-ID').first()
            csid = data['dt_project_id']
        else:
            db_obj = CyberspectScans.objects.filter(ID=data['id']).first()
            csid = data['id']

        if db_obj:
            if 'mobsf_md5' in data:
                db_obj.MOBSF_MD5 = data['mobsf_md5']
            if 'dt_project_id' in data and data['dt_project_id']:
                db_obj.DT_PROJECT_ID = data['dt_project_id']
            if 'intake_end' in data and data['intake_end']:
                db_obj.INTAKE_END = tz(data['intake_end'])
            if 'sast_start' in data and data['sast_start']:
                db_obj.SAST_START = tz(data['sast_start'])
            if 'sast_end' in data and data['sast_end']:
                db_obj.SAST_END = tz(data['sast_end'])
            if 'sbom_start' in data and data['sbom_start']:
                db_obj.SBOM_START = tz(data['sbom_start'])
            if 'sbom_end' in data and data['sbom_end']:
                db_obj.SBOM_END = tz(data['sbom_end'])
            if 'dependency_start' in data and data['dependency_start']:
                db_obj.DEPENDENCY_START = tz(data['dependency_start'])
            if 'dependency_end' in data and data['dependency_end']:
                db_obj.DEPENDENCY_END = tz(data['dependency_end'])
            if 'notification_start' in data and data['notification_start']:
                db_obj.NOTIFICATION_START = tz(data['notification_start'])
            if 'notification_end' in data and data['notification_end']:
                db_obj.NOTIFICATION_END = tz(data['notification_end'])
            if 'success' in data:
                db_obj.SUCCESS = data['success']
            if 'failure_source' in data and data['failure_source']:
                db_obj.FAILURE_SOURCE = data['failure_source']
            if 'failure_message' in data and data['failure_message']:
                db_obj.FAILURE_MESSAGE = data['failure_message']
            if 'file_size_package' in data and data['file_size_package']:
                db_obj.FILE_SIZE_PACKAGE = data['file_size_package']
            if 'file_size_source' in data and data['file_size_source']:
                db_obj.FILE_SIZE_SOURCE = data['file_size_source']
            if 'dependency_types' in data:
                db_obj.DEPENDENCY_TYPES = data['dependency_types']
            db_obj.save()
            return model_to_dict(db_obj)
        else:
            return {'error': f'Scan ID {csid} not found'}
    except Exception as ex:
        exmsg = ''.join(tb.format_exception(None, ex, ex.__traceback__))
        logger.error(exmsg)
        return {'error': str(ex)}


def logout_aws(request):
    """Remove AWS ALB session cookie."""
    resp = HttpResponse(
        '{}',
        content_type='application/json; charset=utf-8')
    for cookie in request.COOKIES:
        resp.set_cookie(cookie, None, -1, -1)
    return resp


@login_required
@permission_required(Permissions.SCAN)
def download_apk(request):
    """Download and APK by package name."""
    package = request.POST['package']
    # Package validated in apk_download()
    context = {
        'status': 'failed',
        'description': 'Unable to download APK',
    }
    res = apk_download(package)
    if res:
        context = res
        context['status'] = 'ok'
        context['package'] = package
    resp = HttpResponse(
        json.dumps(context),
        content_type='application/json; charset=utf-8')
    return resp


@login_required
def search(request, api=False):
    """Search scan by checksum or text."""
    if request.method == 'POST':
        query = request.POST['query']
    else:
        query = request.GET['query']

    if not query:
        msg = 'No search query provided.'
        return print_n_send_error_response(request, msg, api)

    checksum = query if re.match(MD5_REGEX, query) else find_checksum(query)

    if checksum and re.match(MD5_REGEX, checksum):
        db_obj = RecentScansDB.objects.filter(MD5=checksum).first()
        if db_obj:
            url = f'/{db_obj.ANALYZER}/{db_obj.MD5}/'
            if api:
                return {'checksum': db_obj.MD5}
            else:
                return HttpResponseRedirect(url)

    msg = 'You can search by MD5, app name, package name, or file name.'
    return print_n_send_error_response(request, msg, api, 'Scan not found')


def find_checksum(query):
    """Get the first matching checksum from the database."""
    search_fields = ['FILE_NAME', 'PACKAGE_NAME', 'APP_NAME']

    for field in search_fields:
        result = RecentScansDB.objects.filter(
            **{f'{field}__icontains': query}).first()
        if result:
            return result.MD5

    return None

# AJAX


@login_required
@require_http_methods(['POST'])
def scan_status(request, api=False):
    """Get Current Status of a scan in progress."""
    try:
        scan_hash = request.POST['hash']
        if not is_md5(scan_hash):
            return invalid_params(api)
        robj = RecentScansDB.objects.filter(MD5=scan_hash)
        if not robj.exists():
            data = {'status': 'failed', 'error': 'scan hash not found'}
            return send_response(data, api)
        data = {'status': 'ok', 'logs': python_dict(robj[0].SCAN_LOGS)}
    except Exception as exp:
        logger.exception('Fetching Scan Status')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)


def file_download(dwd_file, filename, content_type):
    """HTTP file download response."""
    with open(dwd_file, 'rb') as file:
        wrapper = FileWrapper(file)
        response = HttpResponse(wrapper, content_type=content_type)
        response['Content-Length'] = dwd_file.stat().st_size
        if filename:
            val = f'attachment; filename="{filename}"'
            response['Content-Disposition'] = val
        return response


@login_required
@require_http_methods(['GET'])
def download_binary(request, checksum, api=False):
    """Download binary from uploads directory."""
    try:
        allowed_exts = settings.ALLOWED_EXTENSIONS
        if not is_md5(checksum):
            return HttpResponse(
                'Invalid MD5 Hash',
                status=HTTP_STATUS_404)
        robj = RecentScansDB.objects.filter(MD5=checksum).first()
        if not robj:
            return HttpResponse(
                'Scan hash not found',
                status=HTTP_STATUS_404)
        file_ext = f'.{robj.SCAN_TYPE}'
        if file_ext not in allowed_exts.keys():
            return HttpResponse(
                'Invalid Scan Type',
                status=HTTP_STATUS_404)
        filename = f'{checksum}{file_ext}'
        dwd_file = Path(settings.UPLD_DIR) / checksum / filename
        if not dwd_file.exists():
            return HttpResponse(
                'File not found',
                status=HTTP_STATUS_404)
        return file_download(
            dwd_file,
            sanitize_filename(robj.FILE_NAME),
            allowed_exts[file_ext])
    except Exception:
        logger.exception('Download Binary Failed')
        return HttpResponse(
            'Failed to download file due to an error',
            status=HTTP_SERVER_ERROR)


@login_required
@require_http_methods(['GET'])
def download(request):
    """Download from mobsf downloads directory."""
    root = settings.DWD_DIR
    filename = request.path.replace('/download/', '', 1)
    dwd_file = Path(root) / filename

    # Security Checks
    if '../' in filename or not is_safe_path(root, dwd_file):
        msg = 'Path Traversal Attack Detected'
        return print_n_send_error_response(request, msg)

    # File and Extension Check
    ext = dwd_file.suffix
    allowed_exts = settings.ALLOWED_EXTENSIONS
    if ext in allowed_exts and dwd_file.is_file():
        return file_download(
            dwd_file,
            None,
            allowed_exts[ext])

    # Special Case for Certain Image Files
    if filename.endswith(('screen/screen.png', '-icon.png')):
        return HttpResponse('')

    return HttpResponse(status=HTTP_STATUS_404)


@require_http_methods(['GET'])
def app_info(request):
    """Get mobile app info by user supplied name."""
    appname = request.GET['name']
    db_obj = RecentScansDB.objects \
        .filter(Q(APP_NAME__icontains=appname)
                | Q(USER_APP_NAME__icontains=appname)) \
        .order_by('-TIMESTAMP')
    user = sso_email(request)
    if db_obj.exists():
        e = db_obj[0]
        if user == e.EMAIL or is_admin(request):
            context = {
                'found': True,
                'version': e.USER_APP_VERSION,
                'division': e.DIVISION,
                'country': e.COUNTRY,
                'environment': e.ENVIRONMENT,
                'data_privacy_classification': e.DATA_PRIVACY_CLASSIFICATION,
                'data_privacy_attributes': e.DATA_PRIVACY_ATTRIBUTES,
                'release': e.RELEASE,
                'email': e.EMAIL,
            }
            logger.info('Found existing mobile app information for %s',
                        appname)
            return HttpResponse(json.dumps(context),
                                content_type='application/json', status=200)
        else:
            logger.info('User is not authorized for %s.', appname)
            payload = {'found': False}
            return HttpResponse(json.dumps(payload),
                                content_type='application/json', status=200)
    else:
        logger.info('Unable to find mobile app information for %s',
                    appname)
        payload = {'found': False}
        return HttpResponse(json.dumps(payload),
                            content_type='application/json', status=200)


@login_required
def generate_download(request):
    """Generate downloads for smali/java zip."""
    try:
        logger.info('Generating Downloads')
        md5 = request.GET['hash']
        file_type = request.GET['file_type']
        if (not is_md5(md5)
                or file_type not in ('smali', 'java')):
            msg = 'Invalid download type or hash'
            logger.exception(msg)
            return print_n_send_error_response(request, msg)
        app_dir = Path(settings.UPLD_DIR) / md5
        dwd_dir = Path(settings.DWD_DIR)
        file_name = ''
        if file_type == 'java':
            # For Java zipped source code
            directory = app_dir / 'java_source'
            dwd_file = dwd_dir / f'{md5}-java'
            shutil.make_archive(
                dwd_file.as_posix(), 'zip', directory.as_posix())
            file_name = f'{md5}-java.zip'
        elif file_type == 'smali':
            # For Smali zipped source code
            directory = app_dir / 'smali_source'
            dwd_file = dwd_dir / f'{md5}-smali'
            shutil.make_archive(
                dwd_file.as_posix(), 'zip', directory.as_posix())
            file_name = f'{md5}-smali.zip'
        return redirect(f'/download/{file_name}')
    except Exception:
        msg = 'Generating Downloads'
        logger.exception(msg)
        return print_n_send_error_response(request, msg)


@login_required
@permission_required(Permissions.DELETE)
@require_http_methods(['POST'])
def delete_scan(request, api=False):
    """Delete Scan from DB and remove the scan related files."""
    try:
        if api:
            md5_hash = request.POST['hash']
        else:
            md5_hash = request.POST['md5']

        if not re.match(MD5_REGEX, md5_hash):
            return send_response({'deleted': 'Invalid scan hash'}, api)

        # Delete DB Entries
        scan = RecentScansDB.objects.filter(MD5=md5_hash)
        if not scan.exists():
            return send_response({'deleted': 'Scan not found in Database'}, api)
        if settings.ASYNC_ANALYSIS:
            # Handle Async Tasks
            et = EnqueuedTask.objects.filter(checksum=md5_hash).first()
            if et:
                max_time_passed = now() - et.created_at > timedelta(
                    minutes=settings.ASYNC_ANALYSIS_TIMEOUT)
                if not (et.completed_at or max_time_passed):
                    # Queue is in progress, cannot delete the task
                    return send_response(
                        {'deleted': 'A scan can only be deleted after it is completed'},
                        api)
        # Delete all related DB entries
        EnqueuedTask.objects.filter(checksum=md5_hash).all().delete()
        RecentScansDB.objects.filter(MD5=md5_hash).delete()
        StaticAnalyzerAndroid.objects.filter(MD5=md5_hash).delete()
        StaticAnalyzerIOS.objects.filter(MD5=md5_hash).delete()
        StaticAnalyzerWindows.objects.filter(MD5=md5_hash).delete()
        # Delete Upload Dir Contents
        app_upload_dir = os.path.join(settings.UPLD_DIR, md5_hash)
        if is_dir_exists(app_upload_dir):
            shutil.rmtree(app_upload_dir)
        # Delete Download Dir Contents
        dw_dir = settings.DWD_DIR
        for item in os.listdir(dw_dir):
            item_path = os.path.join(dw_dir, item)
            valid_item = item.startswith(md5_hash + '-')
            # Delete all related files
            if is_file_exists(item_path) and valid_item:
                os.remove(item_path)
            # Delete related directories
            if is_dir_exists(item_path) and valid_item:
                shutil.rmtree(item_path, ignore_errors=True)
        return send_response({'deleted': 'yes'}, api)
    except Exception as exp:
        msg = str(exp)
        exp_doc = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp_doc)
        else:
            return print_n_send_error_response(request, msg, False, exp_doc)


def cyberspect_rescan(apphash, scheduled, sso_user):
    """Get cyberspect scan by hash."""
    rs_obj = RecentScansDB.objects.filter(MD5=apphash).first()
    if not rs_obj:
        return None
    # Get file sizes
    file_path = os.path.join(settings.UPLD_DIR, apphash + '/') \
        + apphash + '.' + rs_obj.SCAN_TYPE
    file_size = os.path.getsize(file_path)
    source_file_size = 0
    if os.path.exists(file_path + '.src'):
        source_file_size = os.path.getsize(file_path + '.src')

    start_time = utcnow()
    scan_id = new_cyberspect_scan(scheduled, apphash, start_time,
                                  file_size, source_file_size, sso_user)
    scan_data = {
        'cyberspect_scan_id': scan_id,
        'hash': apphash,
        'short_hash': get_siphash(apphash),
        'scan_type': rs_obj.SCAN_TYPE,
        'file_name': rs_obj.FILE_NAME,
        'user_app_name': rs_obj.USER_APP_NAME,
        'user_app_version': rs_obj.USER_APP_VERSION,
        'email': rs_obj.EMAIL,
        'rescan': '1',
    }
    cyberspect_scan_intake(scan_data)
    return scan_data


def cyberspect_scan_intake(scan):
    if not settings.AWS_INTAKE_LAMBDA:
        logging.warning('Environment variable AWS_INTAKE_LAMBDA not set')
        return

    lclient = boto3.client('lambda')
    file_path = os.path.join(settings.UPLD_DIR, scan['hash'] + '/') \
        + scan['hash'] + '.' + scan['scan_type']
    if (os.path.exists(file_path + '.src')):
        file_path = file_path + '.src'
    lambda_params = {
        'cyberspect_scan_id': scan['cyberspect_scan_id'],
        'hash': scan['hash'],
        'short_hash': scan['short_hash'],
        'user_app_name': scan['user_app_name'],
        'user_app_version': scan['user_app_version'],
        'scan_type': scan['scan_type'],
        'email': scan['email'],
        'file_name': file_path,
        'rescan': scan['rescan'],
    }
    logger.info('Executing Cyberspect intake lambda: %s',
                settings.AWS_INTAKE_LAMBDA)
    lclient.invoke(FunctionName=settings.AWS_INTAKE_LAMBDA,
                   InvocationType='Event',
                   Payload=json.dumps(lambda_params).encode('utf-8'))
    return


def health(request):
    """Check MobSF system health."""
    # Ensure database access is good
    RecentScansDB.objects.all().first()
    data = {'status': 'OK'}
    return HttpResponse(json.dumps(data),
                        content_type='application/json; charset=utf-8')


class RecentScans(object):

    def __init__(self, request):
        self.request = request

    def recent_scans(self):
        page = self.request.GET.get('page', 1)
        page_size = self.request.GET.get('page_size', 10)
        result = RecentScansDB.objects.all().values().order_by('-TIMESTAMP')
        try:
            paginator = Paginator(result, page_size)
            if (int(page) > paginator.num_pages):
                data = {
                    'content': [],
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }
            else:
                content = paginator.page(page)
                data = {
                    'content': list(content),
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }
        except Exception as exp:
            exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
            logger.error(exmsg)
            data = {'error': str(exp)}
        return data

    def cyberspect_recent_scans(self):
        page = self.request.GET.get('page', 1)
        page_size = self.request.GET.get('page_size', 10)
        cs_scans = CyberspectScans.objects.all()
        result = cs_scans.values().order_by('-INTAKE_START')
        try:
            paginator = Paginator(result, page_size)
            if (int(page) > paginator.num_pages):
                data = {
                    'content': [],
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }
            else:
                content = paginator.page(page)
                data = {
                    'content': list(content),
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }

        except Exception as exp:
            exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
            logger.error(exmsg)
            data = {'error': str(exp)}
        return data

    def cyberspect_completed_scans(self):
        page = self.request.GET.get('page', 1)
        page_size = self.request.GET.get('page_size', 10)
        def_date = datetime.datetime.now(datetime.timezone.utc) \
            - datetime.timedelta(hours=24)
        from_date = tz(self.request.GET.get('from_date', def_date))
        result = CyberspectScans.objects.filter(SCHEDULED=True,
                                                INTAKE_START__gte=from_date) \
            .values().order_by('ID')
        try:
            paginator = Paginator(result, page_size)
            if (int(page) > paginator.num_pages):
                data = {
                    'content': [],
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }
            else:
                content = paginator.page(page)
                for scan in content:
                    # Get app details
                    md5 = scan['MOBSF_MD5']
                    scan_result = RecentScansDB.objects.filter(MD5=md5) \
                        .first()
                    if scan_result:
                        scan['APP_NAME'] = scan_result.APP_NAME
                        scan['VERSION_NAME'] = scan_result.VERSION_NAME
                        scan['PACKAGE_NAME'] = scan_result.PACKAGE_NAME
                        scan['SCAN_TYPE'] = scan_result.SCAN_TYPE
                        scan['DATA_PRIVACY_CLASSIFICATION'] = \
                            scan_result.DATA_PRIVACY_CLASSIFICATION
                        scan['EMAIL'] = scan_result.EMAIL

                        # Get scan vulnerability counts
                        findings = appsec.appsec_dashboard(self.request, md5,
                                                           True)
                        scan['FINDINGS_HIGH'] = len(findings['high']) \
                            if 'high' in findings else 0
                        scan['FINDINGS_WARNING'] = len(findings['warning']) \
                            if 'warning' in findings else 0
                        scan['FINDINGS_INFO'] = len(findings['info']) \
                            if 'info' in findings else 0
                        scan['SECURITY_SCORE'] = findings['security_score']
                data = {
                    'content': list(content),
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }
        except Exception as exp:
            exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
            logger.error(exmsg)
            data = {'error': str(exp)}
        return data

    def release_scans(self):
        page = self.request.GET.get('page', 1)
        page_size = self.request.GET.get('page_size', 10)
        scans = RecentScansDB.objects.filter(RELEASE=True) \
            .exclude(ENVIRONMENT='Decommissioned')
        result = scans.values().order_by('APP_NAME', 'VERSION_NAME')
        try:
            paginator = Paginator(result, page_size)
            if (int(page) > paginator.num_pages):
                data = {
                    'content': [],
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }
            else:
                content = paginator.page(page)
                data = {
                    'content': list(content),
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }
        except Exception as exp:
            exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
            logger.error(exmsg)
            data = {'error': str(exp)}
        return data


def update_scan_timestamp(scan_hash):
    # Update the last scan time.
    tms = timezone.now()
    RecentScansDB.objects.filter(MD5=scan_hash).update(TIMESTAMP=tms)
