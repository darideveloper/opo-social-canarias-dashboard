from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status


class UserMeView(APIView):
    """
    manage user own profile
    - GET: Get user profile
    - PUT: Update user profile
    - DELETE: Delete user account
    """

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
