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

    class Meta:
        model = User
        fields = ["username", "email", "password", "avatar", "last_password"]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        avatar = validated_data.pop("avatar", None)
        last_password = validated_data.pop("last_password", None)

        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data.get("email"),
            password=validated_data["password"],
            is_active=False,  # ⬅ user can’t log in until activation
        )

        models.Profile.objects.create(
            user=user, profile_img=avatar, last_pass=last_password
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
