"""MobSF File Upload and Home Routes."""
import json
import logging
import os
import re
import traceback as tb

from django.conf import settings
from django.db.models import Q
from django.http import HttpResponse
from django.views.decorators.http import require_http_methods
from django.shortcuts import (
    render,
)
from django.forms.models import model_to_dict

from django_q.tasks import async_task

from django.utils import timezone

from mobsf.MobSF.utils import (
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import (
    EnqueuedTask,
    RecentScansDB,
)
# Cyberspect imports
from mobsf.StaticAnalyzer.cyberspect_models import (
    CyberspectScans,
)

from cyberspect.utils import (
    get_siphash,
    is_admin,
    sso_email,
    update_cyberspect_scan,
    utcnow,
)

logger = logging.getLogger(__name__)


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


def cyberspect_scan_intake(upload_or_data, cyberspect_scan_id=None):
    """
    Process scan intake for Cyberspect.

    Args:
        upload_or_data: Either an Upload object or a dictionary with scan data
        cyberspect_scan_id: Optional scan ID (used when upload_or_data is a dict)
    """
    # Handle both Upload objects and plain dictionaries
    if isinstance(upload_or_data, dict):
        # Called from cyberspect_rescan with a dictionary
        scan_data = upload_or_data
        if cyberspect_scan_id:
            scan_data['cyberspect_scan_id'] = cyberspect_scan_id
    else:
        # Called from Upload.upload_api or Upload.upload_html
        scan_data = extract_cyberspect_scan_data(upload_or_data)

    # Use django-q2 async_task to enqueue the scan
    checksum = scan_data['hash']
    file_name = scan_data.get('file_name', 'unknown')
    msg = f'Creating async task for checksum: {checksum}'
    logger.info(msg)

    task_id = async_task(
        'cyberspect.MobSF.views.api.api_static_analysis.scan',
        scan_data,
        task_name=f'scan_{checksum}',
    )

    logger.info(
        '[API_ASYNC_SCAN] Created django-q task with ID: %s for checksum: %s',
        task_id, checksum,
    )

    # Create an EnqueuedTask entry to track the task in the Scan Queue
    enqueued = EnqueuedTask.objects.create(
        task_id=task_id,
        checksum=checksum,
        file_name=file_name[:254],
        status='Enqueued',
        created_at=timezone.now(),
    )
    msg = f'Created EnqueuedTask with ID: {enqueued.id}'
    logger.info(msg)

    # Update intake end time immediately
    update_data = {
        'id': scan_data.get('cyberspect_scan_id'),
        'intake_end': utcnow(),
    }
    update_cyberspect_scan(update_data)
    return


def extract_cyberspect_scan_data(upload_obj):
    """
    Helper function to extract scan data from an Upload object.

    Mimics the populate_data_dict functionality from Scanning class.
    """
    return {
        'cyberspect_scan_id': upload_obj.cyberspect_scan_id,
        'hash': upload_obj.md5,
        'short_hash': upload_obj.short_hash,
        'scan_type': upload_obj.scan_type,
        'file_name': upload_obj.file_name,
        'status': 'success',
        'user_app_name': upload_obj.user_app_name,
        'user_app_version': upload_obj.user_app_version,
        'division': upload_obj.division,
        'environment': upload_obj.environment,
        'country': upload_obj.country,
        'data_privacy_classification': upload_obj.data_privacy_classification,
        'data_privacy_attributes': upload_obj.data_privacy_attributes,
        'email': upload_obj.email,
        'user_groups': upload_obj.user_groups,
        'release': upload_obj.release,
        'rescan': upload_obj.rescan,
        'analyzer': 'static_analyzer',
    }


def get_cyberspect_scan(csid):
    db_obj = CyberspectScans.objects.filter(ID=csid).first()
    if db_obj:
        cs_obj = model_to_dict(db_obj)
        return cs_obj
    return None


def health(request):
    """Check MobSF system health."""
    # Ensure database access is good
    RecentScansDB.objects.all().first()
    data = {'status': 'OK'}
    return HttpResponse(json.dumps(data),
                        content_type='application/json; charset=utf-8')


def logout_aws(request):
    """Remove AWS ALB session cookie."""
    resp = HttpResponse(
        '{}',
        content_type='application/json; charset=utf-8')
    for cookie in request.COOKIES:
        resp.set_cookie(cookie, None, -1, -1)
    return resp


def new_cyberspect_scan(scheduled, md5, start_time, scan_type, sso_user):
    """Create new Cyberspect scan record with calculated file sizes."""
    # Calculate file sizes from saved files
    from pathlib import Path
    from django.conf import settings
    from mobsf.MobSF.utils import file_size

    app_dir = Path(settings.UPLD_DIR) / md5

    # Find the actual file by checking common extensions
    file_path = None
    for ext in ['.apk', '.ipa', '.appx', '.zip', '.xapk', '.apks', '.aab']:
        potential_path = app_dir / f'{md5}{ext}'
        if potential_path.exists():
            file_path = potential_path
            break

    # Calculate file sizes
    file_size_package = file_size(file_path) if file_path and file_path.exists() else 0

    source_file_path = Path(str(file_path) + '.src') if file_path else None
    file_size_source = file_size(
        source_file_path) if source_file_path and source_file_path.exists() else 0
    # Insert new record into CyberspectScans
    new_db_obj = CyberspectScans(
        SCHEDULED=scheduled,
        MOBSF_MD5=md5,
        INTAKE_START=start_time,
        FILE_SIZE_PACKAGE=file_size_package,
        FILE_SIZE_SOURCE=file_size_source,
        EMAIL=sso_user,
    )
    new_db_obj.save()
    return new_db_obj.ID


def scan_metadata(md5):
    """Get scan metadata."""
    if re.match('[0-9a-f]{32}', md5):
        db_obj = RecentScansDB.objects.filter(MD5=md5).first()
        if db_obj:
            return model_to_dict(db_obj)
    return None


def support(request):
    """Support Route."""
    context = {
        'title': 'Support',
        'tenant_static': settings.TENANT_STATIC_URL,
    }
    template = 'general/support.html'
    return render(request, template, context)


def track_failure(self, error_message):
    if self.cyberspect_scan_id == 0:
        return
    data = {
        'id': self.cyberspect_scan_id,
        'success': False,
        'failure_source': 'SAST',
        'failure_message': error_message,
        'sast_end': utcnow(),
    }
    update_cyberspect_scan(data)


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
