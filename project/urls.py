from django.contrib import admin
from django.views.generic import RedirectView
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import routers

from users import views as users_views

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
    # Auth
    path("auth/register/", users_views.RegisterView.as_view(), name="auth_register"),
    path(
        "auth/token/",
        users_views.CustomTokenObtainPairView.as_view(),
        name="token_obtain_pair",
    ),
    path(
        "auth/token/refresh/",
        users_views.CustomTokenRefreshView.as_view(),
        name="token_refresh",
    ),
    path(
        "auth/activate/<str:token>/",
        users_views.ActivateAccountView.as_view(),
        name="activate_account",
    ),
    # Crud endpoints
    path("api/", include(router.urls)),
]

if not settings.STORAGE_AWS:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
