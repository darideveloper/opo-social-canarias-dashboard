from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from jwt_auth import models as jwt_auth_models
from users import serializers
from utils.media import get_media_url


class UserMeView(APIView):
    """
    manage user own profile
    - GET: Get user profile
    - PUT: Update user profile
    - DELETE: Delete user account
    """

    def get(self, request):
        """Get user profile"""

        # Get user and profile
        user = request.user
        profiles = jwt_auth_models.Profile.objects.filter(user=user)
        if profiles.count() == 0:
            return Response(
                {
                    "status": "error",
                    "message": "user_profile_not_found",
                    "data": {},
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        # Return data
        profile = profiles[0]
        return Response(
            {
                "status": "ok",
                "message": "user_profile",
                "data": {
                    "name": profile.name,
                    "email": user.email,
                    "profile_img": (
                        get_media_url(profile.profile_img)
                        if profile.profile_img
                        else None
                    ),
                },
            },
            status=status.HTTP_200_OK,
        )

    def put(self, request):
        """Update user profile"""
        serializer = serializers.UserMeSerializer(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "status": "ok",
                    "message": "user_profile_updated",
                    "data": {},
                },
                status=status.HTTP_200_OK,
            )
        return Response(
            {
                "status": "error",
                "message": "invalid_data",
                "data": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    def delete(self, request):
        """Delete account"""
        user = request.user
        user.delete()

        return Response(
            {
                "status": "ok",
                "message": "account_deleted",
                "data": {},
            },
            status=status.HTTP_200_OK,
        )
