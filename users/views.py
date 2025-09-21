import uuid

from django.conf import settings

from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from users.serializers import RegisterSerializer
from users.serializers import (
    CustomTokenObtainPairSerializer,
    CustomTokenRefreshSerializer,
)
from utils import emails
from users import models


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class CustomTokenRefreshView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer


class RegisterView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.POST)
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
                name=user.username.replace("_", " "),
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


# class ActivateAccountView(APIView):
#     permission_classes = [AllowAny]
#     authentication_classes = []

#     def get(self, request, token):
#         serializer = ActivateAccountSerializer(data={"token": token})
#         if serializer.is_valid():
#             serializer.save()
#             return Response({"message": "Account activated successfully."}, s
# tatus=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
