from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse

def api_root(request):
    return JsonResponse({
        'status': 'online',
        'message': 'API is running',
        'api_version': '1.0.0',
        'api_endpoints': '/api/'
    })

urlpatterns = [
    path('api/', include('tcms_app.urls')),
    path('admin/', admin.site.urls),
    path('', api_root, name='api_root'),  # Add this line for the root endpoint
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)