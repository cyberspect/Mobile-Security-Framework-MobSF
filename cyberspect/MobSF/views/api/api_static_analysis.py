import logging
import os
import traceback as tb
from wsgiref.util import FileWrapper

from django.contrib.auth.models import AnonymousUser
from django.http import (
    HttpRequest,
    HttpResponse,
    QueryDict,
)
from django.views.decorators.csrf import csrf_exempt

from django_q.tasks import async_task

from mobsf.StaticAnalyzer.models import (
    EnqueuedTask,
)
from mobsf.MobSF.views.helpers import request_method
from mobsf.MobSF.views.home import (
    RecentScans,
    generate_download,
)
from mobsf.MobSF.views.api.api_middleware import make_api_response
from mobsf.StaticAnalyzer.views.android.static_analyzer import static_analyzer
from mobsf.StaticAnalyzer.views.common.async_task import (
    mark_task_completed,
    mark_task_started,
)
from mobsf.StaticAnalyzer.views.ios.static_analyzer import static_analyzer_ios
from mobsf.StaticAnalyzer.views.windows import windows

from cyberspect.utils import (
    sso_email,
    update_cyberspect_scan,
    utcnow,
)
from cyberspect.MobSF.views.home import (
    cyberspect_rescan,
    get_cyberspect_scan,
    scan_metadata,
    update_scan,
)


logger = logging.getLogger(__name__)


def _create_mock_request(scan_data, csdata):
    """
    Create a mock Django request object for static analyzers.

    Args:
        scan_data: Dictionary with scan parameters
        csdata: Cyberspect scan data

    Returns:
        HttpRequest: Mock request object
    """
    request = HttpRequest()
    request.method = 'POST'

    # Create a proper QueryDict for POST data
    post_data = QueryDict(mutable=True)
    post_data['hash'] = scan_data['hash']
    post_data['re_scan'] = scan_data.get('rescan', '0')
    request.POST = post_data

    # Set META attributes to mimic API authentication middleware
    request.META['email'] = csdata.get('EMAIL', 'admin@cyberspect.com')
    request.META['role'] = 'FULL_ACCESS'

    # Mark that we're in an async worker to prevent nested async
    request.META['_in_async_worker'] = True

    # Set anonymous user
    request.user = AnonymousUser()

    return request


@request_method(['GET'])
@csrf_exempt
def api_release_scans(request):
    """GET - get release scans."""
    scans = RecentScans(request)
    resp = scans.release_scans()
    if 'error' in resp:
        return make_api_response(resp, 500)
    else:
        return make_api_response(resp, 200)


@request_method(['GET'])
@csrf_exempt
def api_scan_metadata(request):
    """GET - get scan metadata."""
    md5 = request.GET['hash']
    scan = scan_metadata(md5)
    if scan:
        return make_api_response(scan, 200)
    else:
        return make_api_response({'hash': md5}, 404)


@request_method(['POST'])
@csrf_exempt
def api_async_scan(request):
    """POST - Async Scan API."""
    if ('cyberspect_scan_id' in request.POST):
        csdata = get_cyberspect_scan(request.POST['cyberspect_scan_id'])
        if not csdata:
            return make_api_response({'error': 'cyberspect_scan_id not found'},
                                     404)
        scan_data = {
            'cyberspect_scan_id': csdata['ID'],
            'hash': csdata['MOBSF_MD5'],
            'rescan': request.POST.get('rescan', '0'),
        }
    else:
        return make_api_response(
            {'error': 'Missing parameter: cyberspect_scan_id'}, 422)

    # Use django-q2 async_task to enqueue the scan
    task_id = async_task(
        'cyberspect.MobSF.views.api.api_static_analysis.async_scan', scan_data)
    logger.info(
        '[API_ASYNC_SCAN] Created django - q task with ID: %s for checksum: %s',
        task_id, scan_data['hash'],
    )

    # Create EnqueuedTask record to match web upload flow
    try:
        enqueued_task = EnqueuedTask.objects.create(
            task_id=task_id,
            checksum=scan_data['hash'],
            file_name=f"Scan_{scan_data['cyberspect_scan_id']}")
        logger.info(
            '[API_ASYNC_SCAN] Created EnqueuedTask record with ID: %s',
            enqueued_task.id,
        )
    except Exception as e:
        msg = str(e)
        logger.error('[API_ASYNC_SCAN] Failed to create EnqueuedTask record: %s', msg)
        logger.exception(
            '[API_ASYNC_SCAN] EnqueuedTask creation failed with exception details')

    response_message = ('Scan ID ' + request.POST['cyberspect_scan_id']
                        + ' queued for background scanning with task ID: '
                        + str(task_id))
    logger.info(response_message)
    return make_api_response({'message': response_message, 'task_id': task_id}, 202)


@request_method(['POST'])
@csrf_exempt
def api_rescan(request):
    """POST - Rescan API."""
    if ('hash' in request.POST):
        # Create a new CyberspectScans record for an app
        scheduled = request.POST.get('scheduled', True)
        scan_data = cyberspect_rescan(request.POST['hash'], scheduled,
                                      sso_email(request))
        if not scan_data:
            make_api_response({'error': 'Scan hash not found'}, 404)
    else:
        return make_api_response(
            {'error': 'Missing parameter: hash'}, 422)

    response_message = ('App ID ' + request.POST['hash']
                        + ' submitted for background scanning: ID '
                        + str(scan_data['cyberspect_scan_id']))
    logger.info(response_message)
    return make_api_response({'message': response_message}, 202)


@request_method(['GET'])
@csrf_exempt
def api_download(request):
    """GET - Download an app package file."""
    if 'hash' not in request.GET or 'file_type' not in request.GET:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = generate_download(request, True)
    if 'error' in resp:
        if 'No such file or directory' in resp['error']:
            response = make_api_response(resp, 404)
        else:
            response = make_api_response(resp, 500)
    else:
        print(resp)
        wrapper = FileWrapper(
            open(resp['file_name'], 'rb'))
        response = HttpResponse(
            wrapper, status=200, content_type='application/octet-stream')
        response['Content-Length'] = os.path.getsize(resp['file_name'])
        return response
    return response


@request_method(['GET'])
@csrf_exempt
def api_cyberspect_get_scan(request):
    """GET - get Cyberspect scan detail."""
    csid = request.GET['id']
    scan = get_cyberspect_scan(csid)
    if scan:
        return make_api_response(scan, 200)
    else:
        return make_api_response({'id': csid}, 404)


@request_method(['GET'])
@csrf_exempt
def api_cyberspect_recent_scans(request):
    """GET - get recent Cyberspect scans."""
    scans = RecentScans(request)
    resp = scans.cyberspect_recent_scans()
    if 'error' in resp:
        return make_api_response(resp, 500)
    else:
        return make_api_response(resp, 200)


@request_method(['GET'])
@csrf_exempt
def api_cyberspect_completed_scans(request):
    """GET - get completed Cyberspect scans."""
    scans = RecentScans(request)
    resp = scans.cyberspect_completed_scans()
    if 'error' in resp:
        return make_api_response(resp, 500)
    else:
        return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_update_scan(request):
    """POST - Update a record in RecentScansDb."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = update_scan(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_update_cyberspect_scan(request):
    """POST - Update a record in CyberspectScans."""
    resp = update_cyberspect_scan(request.POST.dict())
    if resp:
        if 'error' in resp:
            return make_api_response(resp, 500)
        else:
            return make_api_response(resp, 200)
    else:
        return make_api_response({'id': request.POST['id']}, 404)


def scan(scan_data):
    """Perform static analysis scan using an Upload instance."""
    scan_id = scan_data['cyberspect_scan_id']
    checksum = scan_data['hash']

    try:
        # Extract Cyberspect data from the scan
        csdata = get_cyberspect_scan(scan_id)

        # Check if scan is already in progress - use UPPERCASE key
        if csdata['SAST_START']:
            return

        # Set scan status to 'in progress'
        update_cyberspect_scan({
            'id': csdata['ID'],
            'sast_status': 'in progress',
            'sast_start': utcnow(),
        })

        logger.info(
            '[SCAN] Starting analysis for scan %s, checksum %s',
            scan_id,
            checksum,
        )

        # Create a mock request object for the static analyzers
        request = _create_mock_request(scan_data, csdata)

        # Mark task as started in EnqueuedTask
        checksum = scan_data['hash']
        mark_task_started(checksum)

        response = None
        resp = {}  # Initialize resp to avoid UnboundLocalError
        metadata = scan_metadata(csdata['MOBSF_MD5'])
        scan_type = metadata['SCAN_TYPE']

        # APK, Source Code (Android/iOS) ZIP, SO, JAR, AAR
        if scan_type in {'xapk', 'apk', 'apks', 'zip', 'so', 'jar', 'aar'}:
            resp = static_analyzer(request, checksum, True)
            if 'type' in resp:
                resp = static_analyzer_ios(request, checksum, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)
        # IPA
        elif scan_type in {'ipa', 'dylib', 'a'}:
            resp = static_analyzer_ios(request, checksum, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)
        # APPX
        elif scan_type == 'appx':
            resp = windows.staticanalyzer_windows(request, checksum, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)

        # Record scan end time and failure
        data = {
            'id': csdata['ID'],
            'sast_start': None,
            'sast_end': utcnow(),
        }

        if response and response.status_code == 500:
            data['success'] = False
            data['failure_source'] = 'SAST'
            data['failure_message'] = resp.get('error', 'Unknown error')
            # Mark task as failed
            mark_task_completed(checksum, 'Failed', resp.get('error', 'Unknown error'))
        else:
            data['success'] = True
            update_cyberspect_scan(data)
            # Mark task as completed successfully
            app_name = resp.get('app_name', resp.get('file_name', 'Analysis Completed'))
            mark_task_completed(checksum, app_name, 'Success')

        return response

    except Exception as exp:
        # Log the full traceback
        exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
        logger.error(
            '[SCAN] Error in scan %s: %s',
            scan_id,
            exmsg,
        )

        # Mark scan as failed
        update_cyberspect_scan({
            'id': scan_id,
            'sast_status': 'failed',
            'sast_start': None,  # Clear in-progress flag
            'sast_end': utcnow(),
            'success': False,
            'failure_source': 'SAST',
            'failure_message': str(exp),
        })

        # Mark task as failed
        mark_task_completed(checksum, 'Failed', str(exp))

        return make_api_response(
            {'error': 'Static analysis scan failed.'},
            500,
        )
