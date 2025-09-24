import os

from django.contrib.auth.models import User
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile

from rest_framework import status

from core.tests_base.test_views import BaseTestApiViewsMethods
from jwt_auth.models import Profile
from utils.media import get_media_url


class UserMeViewTestsCase(BaseTestApiViewsMethods):
    """
    Test user me view
    """

    def setUp(self):
        super().setUp(
            endpoint="/users/me/",
            restricted_delete=False,
            restricted_get=False,
            restricted_put=False,
        )

        # Create user and setup credentials
        password = "test_password"
        self.user = User.objects.create_user(
            username="test_user_me@gmail.com",
            email="test_user_me@gmail.com",
            password=password,
            is_active=True,
        )

        # Get the path to your avatar file
        project_path = settings.BASE_DIR
        avatar_path = os.path.join(project_path, "media", "test", "avatar.png")

        # Open the actual file and create a SimpleUploadedFile
        with open(avatar_path, "rb") as f:
            avatar_file = SimpleUploadedFile(
                name="avatar.png", content=f.read(), content_type="image/png"
            )

        self.profile = Profile.objects.create(
            user=self.user,
            name="Test User",
            profile_img=avatar_file,
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
        Expects:
            - The response is a 200 OK
            - The status is ok
            - The message is account_deleted
            - The account is deleted
        """
        response = self.client.delete(self.endpoint)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "ok")
        self.assertEqual(response.data["message"], "account_deleted")

        # Validate account is deleted
        self.assertFalse(User.objects.filter(id=self.user.id).exists())
        self.assertFalse(Profile.objects.filter(id=self.profile.id).exists())

    def test_delete_account_unauthenticated(self):
        """
        Test delete account unauthenticated
        Expects:
            - The response is a 401 UNAUTHORIZED
            - The status is error
            - The message is unauthenticated
            - The account is not deleted
        """
        self.client.credentials()
        response = self.client.delete(self.endpoint)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["status"], "error")

        # Validate account is not deleted
        self.assertTrue(User.objects.filter(id=self.user.id).exists())
        self.assertTrue(Profile.objects.filter(id=self.profile.id).exists())

    def test_get_user_profile(self):
        """
        Test get user profile

        Expects:
            - The response is a 200 OK
            - The status is ok
            - The message is user_profile
            - The data contains the user data
        """

        # Validate response
        response = self.client.get(self.endpoint)
        data = response.data["data"]
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "ok")
        self.assertEqual(response.data["message"], "user_profile")
        self.assertEqual(data["name"], self.profile.name)
        self.assertEqual(data["email"], self.user.email)
        self.assertEqual(data["profile_img"], get_media_url(self.profile.profile_img))

    def test_get_user_profile_unauthenticated(self):
        """
        Test get user profile unauthenticated
        Expects:
            - The response is a 401 UNAUTHORIZED
            - The status is error
            - The message is unauthenticated
        """
        self.client.credentials()
        response = self.client.get(self.endpoint)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["status"], "error")

    def test_get_user_profile_not_found(self):
        """
        Test get user profile not found
        Expects:
            - The response is a 404 NOT FOUND
            - The status is error
            - The message is user_profile_not_found
        """
        self.profile.delete()

        response = self.client.get(self.endpoint)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data["status"], "error")
        self.assertEqual(response.data["message"], "user_profile_not_found")

    def test_get_profile_image(self):
        """
        Test get profile image correctly
        Expects:
            - The response is a 200 OK
            - The status is ok
            - The message is user_profile
            - The profile image starts with "http"
            - The profile image has image name and extension
        """

        response = self.client.get(self.endpoint)
        data = response.data["data"]
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "ok")
        self.assertEqual(response.data["message"], "user_profile")
        self.assertTrue(data["profile_img"].startswith("http"))
        self.assertTrue(data["profile_img"].endswith(".png"))
        self.assertIn("avatar", data["profile_img"])
