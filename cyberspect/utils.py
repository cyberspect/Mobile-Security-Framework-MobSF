
import datetime
import base64
import logging
import os
import traceback as tb

import siphash

from django.conf import settings
from django.forms.models import model_to_dict
from django.utils import timezone
from django.http import JsonResponse
from django.core.handlers.wsgi import WSGIRequest

from mobsf.StaticAnalyzer.cyberspect_models import (
    CyberspectScans,
)
from mobsf.StaticAnalyzer.models import RecentScansDB

logger = logging.getLogger(__name__)


def get_app_versions():
    """Get MobSF and Cyberspect versions from settings."""
    return {
        'version': settings.MOBSF_VER,
        'cversion': settings.CYBERSPECT_VER,
    }


def get_siphash(data):
    """Generate SipHash."""
    data_bytes = bytes.fromhex(data)
    tenant_id = os.getenv('TENANT_ID', 'df73ea3d2b91442a903b6043399b1353')
    sip = siphash.SipHash_2_4(bytes.fromhex(tenant_id), data_bytes)
    response = base64.b64encode(sip.digest()).decode('utf8').replace('=', '')
    return response


def get_usergroups(request):
    """Get user groups from SSO."""
    if (is_admin(request)):
        return settings.ADMIN_GROUP
    else:
        return settings.GENERAL_GROUP


def is_admin(request):
    """Check if a user is admin."""
    if (not isinstance(request, WSGIRequest)):
        return False
    if ('role' in request.META and request.META['role'] == 'FULL_ACCESS'):
        return True
    if (not settings.ADMIN_USERS):
        return False
    if ('email' not in request.META):
        return False
    email = request.META['email']
    if (email and email in settings.ADMIN_USERS.split(',')):
        return True
    return False


def make_api_response(data, status=200):
    """Make API response."""
    resp = JsonResponse(
        data=data,  # lgtm [py/stack-trace-exposure]
        status=status)
    resp['Content-Type'] = 'application/json; charset=utf-8'
    return resp


def model_to_dict_str(instance):
    """Convert model to dict with string values."""
    result = model_to_dict(instance)
    for key, value in result.items():
        result[key] = str(value)
    return result


def sso_email(request):
    """Get user email from SSO."""
    if ('email' in request.META) and (request.META['email']):
        return request.META['email']
    else:
        return None


def tz(value):
    """Format datetime object with timezone, ensuring UTC."""
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            # Naive datetime, assume UTC
            return timezone.make_aware(value, datetime.timezone.utc)
        else:
            # Aware datetime, convert to UTC
            return value.astimezone(datetime.timezone.utc)
    # Parse string into time zone aware datetime, assume UTC
    value = str(value).replace('T', ' ').replace('Z', '').replace('+00:00', '')
    unware_time = datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S.%f')
    return timezone.make_aware(unware_time, datetime.timezone.utc)


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
            if 'intake_start' in data and data['intake_start']:
                db_obj.INTAKE_START = tz(data['intake_start'])
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


def update_scan_timestamp(scan_hash):
    # Update the last scan time.
    tms = timezone.now()
    RecentScansDB.objects.filter(MD5=scan_hash).update(TIMESTAMP=tms)


def utcnow():
    """Return timezone aware UTC now."""
    return timezone.now()
