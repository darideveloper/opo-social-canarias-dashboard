from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import User

from rest_framework import serializers
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer,
)

from users import models


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)  # Call the parent method to generate tokens

        # Customize the response structure
        return {"status": "ok", "message": "generated", "data": data}


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)  # Call the parent method to generate tokens

        # Customize the response structure
        return {"status": "ok", "message": "refreshed", "data": data}


class RegisterSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField(required=False)
    last_password = serializers.CharField(required=False, write_only=True)
    name = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ["email", "password", "avatar", "last_password", "name"]
        extra_kwargs = {"password": {"write_only": True}}
        
    def validate_email(self, value):
        """Validate if user with this email already exists"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                {"email": "duplicated_email"}
            )
        return value

    def create(self, validated_data):
        
        # Get text data from validated data
        last_password = validated_data.get("last_password", None)
        name = validated_data.get("name", None)
        email = validated_data.get("email")
        password = validated_data.get("password")
        
        # Get avatar as image field
        avatar = validated_data.get("avatar")

        # Create new user
        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            is_active=False,  # ⬅ user can’t log in until activation
        )

        models.Profile.objects.create(
            user=user, name=name, profile_img=avatar, last_pass=last_password
        )
        return user


class ActivateAccountSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate_token(self, value):
        """Check if tokern exists and its less than 1 hour"""
        tokens_lifetime = settings.CUSTOM_TOKENS_LIFETIME_HOURS

        # Validate if token exists
        try:
            token = models.TempToken.objects.get(token=value, type="sign_up")
        except models.TempToken.DoesNotExist:
            raise serializers.ValidationError("Invalid token.")

        # Validate token expiration and if it's active
        token_expiration = token.created_at + timedelta(hours=tokens_lifetime)
        if token.is_active and token_expiration > timezone.now():
            return token
        raise serializers.ValidationError("Invalid token.")

    def save(self):
        """Activate user"""

        # Disable token
        token = models.TempToken.objects.get(token=self.validated_data["token"])
        token.is_active = False
        token.save()

        # Activate user
        user = token.profile.user
        user.is_active = True
        user.save()

        return token
