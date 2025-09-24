from django.contrib.auth.models import User

from rest_framework import status

from core.tests_base.test_views import BaseTestApiViewsMethods
from jwt_auth.models import Profile


class UserMeViewTestsCase(BaseTestApiViewsMethods):
    """
    Test user me view
    """

    def setUp(self):
        super().setUp(
            endpoint="/users/me/",
            restricted_delete=False,
        )
        
        # Create user and setup credentials
        password = "test_password"
        self.user = User.objects.create_user(
            username="test_user_me@gmail.com",
            email="test_user_me@gmail.com",
            password=password,
            is_active=True,
        )

        self.profile = Profile.objects.create(
            user=self.user,
            name="Test User",
        )

        response = self.client.post(
            "/auth/token/",
            {"username": self.user.username, "password": password},
        )
        self.access_token = response.data["data"]["access"]
        
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")

    def test_delete_account(self):
        """
        Test delete account
        """
        response = self.client.delete(self.endpoint)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "ok")
        self.assertEqual(response.data["message"], "account_deleted")
