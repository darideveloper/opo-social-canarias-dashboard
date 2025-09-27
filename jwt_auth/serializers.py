from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import User

from rest_framework import serializers
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer,
)

from jwt_auth import models


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        super().validate(attrs)

        # Don't return tokens in response - they'll be set as HttpOnly cookies
        return {"status": "ok", "message": "generated", "data": {}}


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        super().validate(attrs)  # Call the parent method to generate tokens

        # Don't return tokens in response - they'll be set as HttpOnly cookies
        return {"status": "ok", "message": "refreshed", "data": {}}


class RegisterSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField(required=False)
    email = serializers.EmailField(required=True)
    name = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ["email", "password", "avatar", "name"]
        extra_kwargs = {"password": {"write_only": True}}
        
    def validate_email(self, value):
        """Validate if user with this email already exists"""
        is_error = False
        if User.objects.filter(email=value, is_active=True).exists():
            is_error = True
        if User.objects.filter(username=value, is_active=True).exists():
            is_error = True
            
        # Return error if there is an active user with the same email
        if is_error:
            raise serializers.ValidationError("duplicated_email")
        return value

    def save(self):
        
        # Get text data from validated data
        name = self.validated_data.get("name", None)
        email = self.validated_data.get("email")
        password = self.validated_data.get("password")
        
        # Get avatar as image field
        avatar = self.validated_data.get("avatar")
        
        # Get inactive user (if already registered)
        user = User.objects.filter(email=email)
        
        if user.exists():
            # Overwrite user in second register if not active
            user = user.first()
            user.username = email
        else:
            # Create new user if first register
            user = User.objects.create_user(
                username=email,
                email=email,
                is_active=False,
            )
            
        user.set_password(password)
        user.save()

        # Delete old profiles
        models.Profile.objects.filter(user=user).delete()
        
        # Create new profile
        models.Profile.objects.create(
            user=user, name=name, profile_img=avatar
        )
        return user


class TokenSerializer(serializers.Serializer):
    token = serializers.CharField()
    token_type = serializers.CharField()

    def validate_token(self, value):
        """Check if token exists and its less than live time"""
        tokens_lifetime = settings.CUSTOM_TOKENS_LIFETIME_HOURS

        # Validate if token exists
        token_type = getattr(self, 'token_type', None)
        if not token_type:
            raise serializers.ValidationError("Token type not specified.")
            
        try:
            token = models.TempToken.objects.get(
                token=value, type=token_type
            )
        except models.TempToken.DoesNotExist:
            raise serializers.ValidationError("Invalid token.")

        # Validate token expiration and if it's active
        token_expiration = token.created_at + timedelta(hours=tokens_lifetime)
        if token.is_active and token_expiration > timezone.now():
            return token
        raise serializers.ValidationError("Invalid token.")

    def save(self):
        """Save token"""
        token = models.TempToken.objects.get(token=self.validated_data["token"])
        token.is_active = False
        token.save()
        return token


class ActivateAccountSerializer(TokenSerializer):
    # "token" field from parent class
    token_type = "sign_up"

    def save(self):
        """Activate user"""

        token = super().save()

        # Activate user
        user = token.profile.user
        user.is_active = True
        user.save()

        return token


class ResetPasswordSerializer(TokenSerializer):
    # "token" field from parent class
    token_type = "pass"
    new_password = serializers.CharField(required=True)

    def save(self):
        """Reset password"""
        token = super().save()

        # Update user password
        user = token.profile.user
        user.set_password(self.validated_data["new_password"])
        user.save()

        return token


class RecoverPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        """Check if email exists"""
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email not found.")
        return value
