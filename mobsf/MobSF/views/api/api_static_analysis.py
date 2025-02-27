# -*- coding: utf_8 -*-
"""MobSF REST API V 1."""
import logging
import os
from wsgiref.util import FileWrapper

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from mobsf.MobSF.utils import (
    get_scan_logs,
    sso_email,
)
from mobsf.MobSF.views.helpers import request_method
from mobsf.MobSF.views.home import (
    RecentScans,
    Upload,
    cyberspect_rescan,
    delete_scan,
    generate_download,
    get_cyberspect_scan,
    scan,
    scan_metadata,
    search,
    update_cyberspect_scan,
    update_scan,
)
from mobsf.MobSF.utils import make_api_response
from mobsf.StaticAnalyzer.views.android.views import view_source
from mobsf.StaticAnalyzer.views.ios.views import view_source as ios_view_source
from mobsf.StaticAnalyzer.views.common.async_task import list_tasks
from mobsf.StaticAnalyzer.views.common.shared_func import compare_apps
from mobsf.StaticAnalyzer.views.common.suppression import (
    delete_suppression,
    list_suppressions,
    suppress_by_files,
    suppress_by_rule_id,
)
from mobsf.StaticAnalyzer.views.common.pdf import pdf
from mobsf.StaticAnalyzer.views.common.appsec import appsec_dashboard

logger = logging.getLogger(__name__)


@request_method(['POST'])
@csrf_exempt
def api_upload(request):
    """POST - Upload API."""
    upload = Upload(request)
    resp, code = upload.upload_api()
    return make_api_response(resp, code)


@request_method(['GET'])
@csrf_exempt
def api_recent_scans(request):
    """GET - get recent scans."""
    scans = RecentScans(request)
    resp = scans.recent_scans()
    if 'error' in resp:
        return make_api_response(resp, 500)
    else:
        return make_api_response(resp, 200)


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
def api_scan(request):
    """POST - Scan API."""
    params = {'cyberspect_scan_id', 'hash'}
    if set(request.POST).intersection(params) != params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)

    return scan(request)


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

    response_message = 'App ID ' + request.POST['hash'] \
        + ' submitted for background scanning: ID ' \
        + str(scan_data['cyberspect_scan_id'])
    logging.info(response_message)
    return make_api_response({'message': response_message}, 202)


@request_method(['POST'])
@csrf_exempt
def api_scan_logs(request):
    """POST - Get Scan logs."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = get_scan_logs(request.POST['hash'])
    if not resp:
        return make_api_response(
            {'error': 'No scan logs found'}, 400)
    return make_api_response({'logs': resp}, 200)


@request_method(['POST'])
@csrf_exempt
def api_tasks(request):
    """POST - Get Scan Queue."""
    resp = list_tasks(request, True)
    if not resp:
        return make_api_response(
            {'error': 'Scan queue empty'}, 400)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_delete_scan(request):
    """POST - Delete a Scan."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = delete_scan(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


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


@request_method(['POST'])
@csrf_exempt
def api_pdf_report(request):
    """Generate and Download PDF."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = pdf(
        request,
        request.POST['hash'],
        api=True)
    if 'error' in resp:
        if resp.get('error') == 'Invalid scan hash':
            response = make_api_response(resp, 400)
        else:
            response = make_api_response(resp, 500)
    elif 'pdf_dat' in resp:
        response = HttpResponse(
            resp['pdf_dat'], content_type='application/pdf')
        response['Access-Control-Allow-Origin'] = '*'
    elif resp.get('report') == 'Report not Found':
        response = make_api_response(resp, 404)
    else:
        response = make_api_response(
            {'error': 'PDF Generation Error'}, 500)
    return response


@request_method(['POST'])
@csrf_exempt
def api_json_report(request):
    """Generate JSON Report."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = pdf(
        request,
        request.POST['hash'],
        api=True,
        jsonres=True)
    if 'error' in resp:
        if resp.get('error') == 'Invalid scan hash':
            response = make_api_response(resp, 400)
        else:
            response = make_api_response(resp, 500)
    elif 'report_dat' in resp:
        response = make_api_response(resp['report_dat'], 200)
    elif resp.get('report') == 'Report not Found':
        response = make_api_response(resp, 404)
    else:
        response = make_api_response(
            {'error': 'JSON Generation Error'}, 500)
    return response


@request_method(['POST'])
@csrf_exempt
def api_search(request):
    """Search by checksum or text."""
    if 'query' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = search(request, api=True)
    if 'checksum' in resp:
        request.POST = {'hash': resp['checksum']}
        return api_json_report(request)
    elif 'error' in resp:
        return make_api_response(resp, 404)


@request_method(['POST'])
@csrf_exempt
def api_view_source(request):
    """View Source for android & ios source file."""
    params = {'file', 'type', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    if request.POST['type'] in {'eclipse', 'studio',
                                'apk', 'java', 'smali'}:
        resp = view_source.run(request, api=True)
    else:
        resp = ios_view_source.run(request, api=True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_compare(request):
    """Compare 2 apps."""
    params = {'hash1', 'hash2'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = compare_apps(
        request,
        request.POST['hash1'],
        request.POST['hash2'],
        True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_scorecard(request):
    """Generate App Score Card."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = appsec_dashboard(
        request,
        request.POST['hash'],
        api=True)
    if 'error' in resp:
        if resp.get('error') == 'Invalid scan hash':
            response = make_api_response(resp, 400)
        else:
            response = make_api_response(resp, 500)
    elif 'hash' in resp:
        response = make_api_response(resp, 200)
    elif 'not_found' in resp:
        response = make_api_response(resp, 404)
    else:
        response = make_api_response(
            {'error': 'JSON Generation Error'}, 500)
    return response


@request_method(['POST'])
@csrf_exempt
def api_suppress_by_rule_id(request):
    """POST - Suppress a rule by id."""
    params = {'rule', 'type', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = suppress_by_rule_id(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_suppress_by_files(request):
    """POST - Suppress a rule by files."""
    params = {'rule', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = suppress_by_files(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_list_suppressions(request):
    """POST - View Suppressions."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = list_suppressions(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_delete_suppression(request):
    """POST - Delete a suppression."""
    params = {'kind', 'type', 'rule', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = delete_suppression(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
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
