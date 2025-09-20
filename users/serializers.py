from django.contrib.auth.models import User
from rest_framework import serializers
from .models import Profile

from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer,
)


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

        Profile.objects.create(user=user, avatar=avatar, last_password=last_password)
        return user
