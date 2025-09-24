from django.contrib import admin
from django.views.generic import RedirectView
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import routers

from jwt_auth import urls as auth_urls
from users import urls as user_urls

# Setup drf router
router = routers.DefaultRouter()

urlpatterns = [
    path("admin/", admin.site.urls),
    # Redirects
    path("", RedirectView.as_view(url="/admin/"), name="home-redirect-admin"),
    path(
        "accounts/login/",
        RedirectView.as_view(url="/admin/"),
        name="login-redirect-admin",
    ),
    
    # Crud endpoints
    path("api/", include(router.urls)),
    
    # Apps custom endpoints
    path("auth/", include(auth_urls)),
    path("users/", include(user_urls)),
]

if not settings.STORAGE_AWS:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
