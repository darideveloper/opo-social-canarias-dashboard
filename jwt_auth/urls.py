from django.urls import path

from jwt_auth import views as auth_views

urlpatterns = [

    # Auth
    path("register/", auth_views.RegisterView.as_view(), name="auth_register"),
    path(
        "token/",
        auth_views.CustomTokenObtainPairView.as_view(),
        name="token_obtain_pair",
    ),
    path(
        "token/refresh/",
        auth_views.CustomTokenRefreshView.as_view(),
        name="token_refresh",
    ),
    path(
        "logout/",
        auth_views.LogoutView.as_view(),
        name="logout",
    ),
    path(
        "activate/",
        auth_views.ActivateAccountView.as_view(),
        name="activate_account",
    ),
    path(
        "password/reset/",
        auth_views.PasswordResetView.as_view(),
        name="password_reset",
    ),
]