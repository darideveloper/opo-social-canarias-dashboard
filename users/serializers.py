from rest_framework import serializers

from jwt_auth import models as jwt_auth_models


class UserMeSerializer(serializers.Serializer):
    name = serializers.CharField(required=False)
    profile_img = serializers.ImageField(required=False)
    password = serializers.CharField(required=False)

    def create(self, validated_data):
        """Create user profile"""
        
        # get user and profile
        user = self.context["request"].user
        profile = jwt_auth_models.Profile.objects.get(user=user)
        
        # raise error if not data to update
        if not validated_data:
            raise serializers.ValidationError({"fields": "no_data"})

        # update data
        if validated_data.get("name", None):
            profile.name = validated_data["name"]
        if validated_data.get("profile_img", None):
            profile.profile_img = validated_data["profile_img"]
        if validated_data.get("password", None):
            user.set_password(validated_data["password"])
            user.save()
        profile.save()
        
        # return profile
        return profile
