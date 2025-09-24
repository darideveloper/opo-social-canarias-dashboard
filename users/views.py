from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status


class DeleteAccountView(APIView):
    """
    Delete account by token with success or error message
    """

    def post(self, request):
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
