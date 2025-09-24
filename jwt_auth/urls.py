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
        "activate/",
        auth_views.ActivateAccountView.as_view(),
        name="activate_account",
    ),
    path(
        "recover/",
        auth_views.RecoverPasswordView.as_view(),
        name="recover_password",
    ),
    path(
        "reset/",
        auth_views.ResetPasswordView.as_view(),
        name="reset_password",
    ),
]