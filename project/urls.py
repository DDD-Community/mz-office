from django.contrib import admin
from django.urls import path, include
from django.conf.urls.static import static
from django.conf import settings
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

import app.views

# 기존 스웨거 문서
schema_view = get_schema_view(
    openapi.Info(
        title="MzOffice API",
        default_version='v1',
        description="MzOffice API description",
        terms_of_service="https://www.yourapp.com/terms/",
        contact=openapi.Contact(email="jjs9536@gamil.com"),
        license=openapi.License(name="Your License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('v1/', include('question.urls')),
    path('v1/', include('app.urls')),
    path('', app.views.index, name='index'),
    path('oauth/', include('oauth.urls')),
    path('users/', include('users.urls', namespace='users')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)