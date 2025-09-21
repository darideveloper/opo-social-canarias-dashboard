import uuid

from django.conf import settings
from django.shortcuts import redirect

from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from users import serializers
from utils import emails
from users import models


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom token obtain pair
    """

    serializer_class = serializers.CustomTokenObtainPairSerializer


class CustomTokenRefreshView(TokenRefreshView):
    """
    Custom token refresh
    """

    serializer_class = serializers.CustomTokenRefreshSerializer


class RegisterView(APIView):
    """
    Register new user generate sign up token and send email
    """

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        serializer = serializers.RegisterSerializer(data=request.POST)
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
                name=user.name,
                texts=[
                    "Thank you for signing up!",
                    "Your account has been created successfully.",
                    "Just one more step to start using it.",
                ],
                cta_link=f"{settings.HOST}/auth/activate/{id_token}/",
                cta_text="Activate Now",
                to_email=serializer.validated_data["email"],
            )

            # return reponse
            user = serializer.save()
            message = "Account created successfully."
            message += " Please check your email to activate your account."
            return Response(
                {
                    "message": message,
                    "user": {
                        "username": user.username,
                        "email": user.email,
                    },
                },
                status=status.HTTP_201_CREATED,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ActivateAccountView(APIView):
    """
    Activate account by token and redirect to landing page
    with success or error message
    """

    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request, token):

        redirect_page = settings.LANDING_PAGE
        error_param = "status=error&message-code=account-activation-failed"
        success_param = "status=success&message-code=account-activated"
        error_page = f"{redirect_page}?{error_param}"
        success_page = f"{redirect_page}?{success_param}"

        serializer = serializers.ActivateAccountSerializer(data={"token": token})
        if serializer.is_valid():
            serializer.save()
            return redirect(success_page)
        return redirect(error_page)


class RecoverPasswordView(APIView):
    """
    Request password recovery by email and send email with recovery token
    """

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
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
                type="reset_password",
            )

            # Submit recovery email
            emails.send_email(
                subject="Recover your password",
                name=profile.name,
                texts=["Please click the link below to recover your password."],
                cta_link=f"{settings.HOST}/auth/reset/{id_token}/",
                cta_text="Recover Now",
                to_email=serializer.validated_data["email"],
            )

            return Response(
                {
                    "status": "ok",
                    "message": "Recovery email sent successfully.",
                    "data": {
                        "email": serializer.validated_data["email"],
                    },
                }
            )
        return Response(
            {
                "status": "error",
                "message": "Invalid email.",
                "data": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
