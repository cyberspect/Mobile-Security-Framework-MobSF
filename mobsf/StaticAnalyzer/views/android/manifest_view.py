# -*- coding: utf_8 -*-
"""Module for manifest_view."""

import logging
import os
import re
from pathlib import Path

from django.conf import settings
from django.shortcuts import render

from mobsf.MobSF.utils import (
    error_response,
    is_admin,
)
from mobsf.StaticAnalyzer.views.android.manifest_utils import (
    get_manifest_file,
)

logger = logging.getLogger(__name__)


def run(request):
    """View the manifest."""
    try:
        directory = settings.BASE_DIR  # BASE DIR
        md5 = request.GET['md5']  # MD5
        typ = request.GET['type']  # APK or SOURCE
        match = re.match('^[0-9a-f]{32}$', md5)
        if match and (typ in ['eclipse', 'studio', 'apk', 'aar']):
            app_dir = os.path.join(
                settings.UPLD_DIR, md5 + '/')  # APP DIRECTORY
            tools_dir = os.path.join(
                directory, 'StaticAnalyzer/tools/')  # TOOLS DIR
            app_path = os.path.join(app_dir, md5 + '.apk')
            manifest_file = get_manifest_file(
                app_dir,
                app_path,
                tools_dir,
                typ)
            mfile = Path(manifest_file)
            if mfile.exists():
                manifest = mfile.read_text('utf-8', 'ignore')
            else:
                manifest = ''
            context = {
                'title': 'AndroidManifest.xml',
                'file': 'AndroidManifest.xml',
                'data': manifest,
                'type': 'xml',
                'sqlite': {},
                'version': settings.MOBSF_VER,
                'is_admin': is_admin(request),
            }
            template = 'general/view.html'
            return render(request, template, context)
    except Exception:
        logger.exception('Viewing AndroidManifest.xml')
        return error_response(request,
                              'Error Viewing AndroidManifest.xml')
