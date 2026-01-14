
from .utils import get_app_versions

from cyberspect.utils import is_admin, sso_email

from mobsf.StaticAnalyzer.models import RecentScansDB


def is_admin_processor(request):
    """Expose is_admin context to all templates."""
    return {'is_admin': is_admin(request)}


def recent_scans_processor(request):
    """Expose recent scans to all templates."""
    # Check if user attribute exists and is authenticated
    if hasattr(request, 'user') and request.user.is_authenticated:
        scans = RecentScansDB.objects.all()
        if not is_admin(request):
            email_filter = sso_email(request)
            if not email_filter:
                return {'recent_scans': []}  # No email, no scans for non-admin
            scans = scans.filter(EMAIL__contains=email_filter)
        return {'recent_scans': scans.order_by('-TIMESTAMP')[:5]}
    # Return empty list instead of empty dict for consistency
    return {'recent_scans': []}


def app_versions_processor(request):
    """Expose version numbers to all templates."""
    return get_app_versions()
