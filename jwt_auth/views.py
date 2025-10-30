import uuid

from django.conf import settings

from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken

from jwt_auth import serializers, models
from utils import emails


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom token obtain pair with HttpOnly cookies
    """

    serializer_class = serializers.CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Get the user and generate tokens
        user = serializer.user
        refresh = RefreshToken.for_user(user)

        # Create response
        response_data = serializer.validated_data
        response = Response(response_data, status=status.HTTP_200_OK)

        # Set HttpOnly cookies
        cookie_kwargs = {
            "httponly": True,
            "secure": not settings.DEBUG,  # Use secure cookies in production
            "samesite": "Lax",
            "max_age": settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds(),
        }
        if settings.COOKIE_DOMAIN:
            cookie_kwargs["domain"] = settings.COOKIE_DOMAIN
            
        response.set_cookie("access_token", str(refresh.access_token), **cookie_kwargs)
        response.set_cookie("refresh_token", str(refresh), **cookie_kwargs)

        return response


class CustomTokenRefreshView(TokenRefreshView):
    """
    Custom token refresh with HttpOnly cookies
    """

    serializer_class = serializers.CustomTokenRefreshSerializer

    def post(self, request, *args, **kwargs):
        # Get refresh token from cookie instead of request body
        refresh_token = request.COOKIES.get("refresh_token")
        if not refresh_token:
            return Response(
                {"status": "error", "message": "refresh_token_missing", "data": {}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Create serializer with token from cookie
        serializer = self.get_serializer(data={"refresh": refresh_token})

        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            # Handle invalid token gracefully
            return Response(
                {"status": "error", "message": "invalid_token", "data": {}},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Generate new tokens
        refresh = RefreshToken(refresh_token)
        new_access_token = refresh.access_token

        # Create response
        response_data = serializer.validated_data
        response = Response(response_data, status=status.HTTP_200_OK)

        # Set new access token cookie
        cookie_kwargs = {
            "httponly": True,
            "secure": not settings.DEBUG,
            "samesite": "Strict",
            "max_age": settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds(),
        }
        if settings.COOKIE_DOMAIN:
            cookie_kwargs["domain"] = settings.COOKIE_DOMAIN
            
        response.set_cookie("access_token", str(new_access_token), **cookie_kwargs)

        return response


class RegisterView(APIView):
    """
    Register new user generate sign up token and send email
    """

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        serializer = serializers.RegisterSerializer(data=request.data)
        if serializer.is_valid():

            # Create data and get profile
            user = serializer.save()
            profile = models.Profile.objects.get(user=user)

            # Create activation token
            id_token = uuid.uuid4().hex[:16]
            models.TempToken.objects.create(
                profile=profile,
                token=id_token,
                type="sign_up",
            )

            # Submit activation email
            emails.send_email(
                subject="Activate your account",
                name=user.profile.name,
                texts=[
                    "Thank you for signing up!",
                    "Your account has been created successfully.",
                    "Just one more step to start using it.",
                ],
                cta_link=f"{settings.FRONTEND_URL}/activate/{id_token}/",
                cta_text="Activate Now",
                to_email=serializer.validated_data["email"],
            )

            # return reponse
            return Response(
                {
                    "status": "ok",
                    "message": "account_created",
                    "data": {
                        "email": user.email,
                    },
                },
                status=status.HTTP_201_CREATED,
            )

        return Response(
            {
                "status": "error",
                "message": "invalid_data",
                "data": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class ActivateAccountView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        serializer = serializers.ActivateAccountSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "status": "ok",
                    "message": "account_activated",
                    "data": {},
                },
                status=status.HTTP_200_OK,
            )
        return Response(
            {
                "status": "error",
                "message": "account_activation_failed",
                "data": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class PasswordResetView(APIView):
    """
    Password reset functionality:
    - POST: Request password recovery by email (with token)
    - PUT: Reset password by token
    """

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        """
        Request password recovery by email and send email with recovery token
        """
        serializer = serializers.RecoverPasswordSerializer(data=request.data)
        if serializer.is_valid():

            # Get profile
            profile = models.Profile.objects.get(
                user__email=serializer.validated_data["email"]
            )

            # Create a new recovery token
            id_token = uuid.uuid4().hex[:16]
            models.TempToken.objects.create(
                profile=profile,
                token=id_token,
                type="pass",
            )

            # Submit recovery email
            emails.send_email(
                subject="Recover your password",
                name=profile.name,
                texts=["Please click the link below to recover your password."],
                cta_link=f"{settings.FRONTEND_URL}/auth/reset/{id_token}/",
                cta_text="Recover Now",
                to_email=serializer.validated_data["email"],
            )

            return Response(
                {
                    "status": "ok",
                    "message": "recovery_email_sent",
                    "data": {
                        "email": serializer.validated_data["email"],
                    },
                }
            )
        return Response(
            {
                "status": "error",
                "message": "error_sending_recovery_email",
                "data": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    def put(self, request):
        """
        Reset password by token with success or error message
        """
        serializer = serializers.ResetPasswordSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "status": "ok",
                    "message": "password_reset",
                    "data": {},
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {
                "status": "error",
                "message": "error_resetting_password",
                "data": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class LogoutView(APIView):
    """
    Logout user by clearing HttpOnly cookies
    """

    permission_classes = [AllowAny]

    def post(self, request):
        response = Response(
            {"status": "ok", "message": "logged_out", "data": {}},
            status=status.HTTP_200_OK,
        )

        # Clear cookies
        delete_kwargs = {}
        if settings.COOKIE_DOMAIN:
            delete_kwargs["domain"] = settings.COOKIE_DOMAIN
            
        response.delete_cookie("access_token", **delete_kwargs)
        response.delete_cookie("refresh_token", **delete_kwargs)

        return response
