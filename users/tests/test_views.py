import os

from django.contrib.auth.models import User
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile

from rest_framework.response import Response
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
        self.password = "test_password"
        self.user = User.objects.create_user(
            username="test_user_me@gmail.com",
            email="test_user_me@gmail.com",
            password=self.password,
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
            {"username": self.user.username, "password": self.password},
        )
        self.access_token = response.cookies["access_token"].value

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")

        # Setup data
        new_name = "New Name"
        new_profile_img_path = os.path.join(
            settings.BASE_DIR, "media", "test", "avatar.png"
        )
        with open(new_profile_img_path, "rb") as f:
            new_profile_img = SimpleUploadedFile(
                name="new_avatar.png", content=f.read(), content_type="image/png"
            )
        new_password = "new_password"

        self.update_data = {
            "name": new_name,
            "profile_img": new_profile_img,
            "password": new_password,
        }

        # Additional apis
        self.token_obtain_url = "/auth/token/"

    def __validate_login(self, can_login: bool = True, password: str = None):
        """
        Validate login

        Args:
            can_login: bool to check if login is successful
            password: str to check if password is correct
        """

        if not password:
            password = self.update_data["password"]

        response = self.client.post(
            self.token_obtain_url,
            {
                "username": self.user.username,
                "password": password,
            },
        )
        if can_login:
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data["status"], "ok")
            self.assertEqual(response.data["message"], "generated")
        else:
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
            self.assertEqual(response.data["status"], "error")

    def __validate_update_data(
        self,
        response: Response,
        check_name: bool = True,
        check_avatar: bool = True,
        check_password: bool = True,
    ):
        """
        Validate update data

        Args:
            response: Response object
            check_name: bool to check if name is updated
            check_avatar: bool to check if avatar is updated
            check_password: bool to check if password is updated
        """
        # Validate response
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "ok")
        self.assertEqual(response.data["message"], "user_profile_updated")

        # Validate updated data in db
        self.profile.refresh_from_db()
        self.user.refresh_from_db()
        if check_name:
            self.assertEqual(self.profile.name, self.update_data["name"])
        if check_avatar:
            self.assertTrue(self.profile.profile_img.name.endswith(".png"))
            self.assertIn("new_avatar", self.profile.profile_img.name)

        # Try to login with new password
        if check_password:
            self.__validate_login(can_login=True, password=self.update_data["password"])

    def __validate_data_no_updated(
        self, response: Response, check_password: bool = True
    ):
        """
        Validate that the data is not updated

        Args:
            response: Response object
            check_password: bool to check if password is updated
        """
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["status"], "error")

        # Validate data no updated
        self.profile.refresh_from_db()
        self.user.refresh_from_db()
        self.assertNotEqual(self.profile.name, self.update_data["name"])
        self.assertNotEqual(self.profile.profile_img, self.update_data["profile_img"])

        # Validate user cannot login with new password
        if check_password:
            self.__validate_login(
                can_login=False, password=self.update_data["password"]
            )

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
        
    def test_get_user_profile_no_avatar(self):
        """
        Test get user profile no avatar
        Expects:
            - The response is a 200 OK
            - The status is ok
            - The message is user_profile
            - The profile image is None
        """
        
        # Delete avatar
        self.profile.profile_img.delete()
        self.profile.save()

        response = self.client.get(self.endpoint)
        data = response.data["data"]
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "ok")
        self.assertEqual(response.data["message"], "user_profile")
        self.assertIsNone(data["profile_img"])

    def test_put_user_profile(self):
        """
        Test put user profile (update full data)
        Expects:
            - The response is a 200 OK
            - The status is ok
            - The message is user_profile_updated
            - Name is updated
            - Profile image is updated
            - Password is updated
        """

        # Setup new data

        # validate response (submit data as put html form)
        response = self.client.put(
            self.endpoint,
            self.update_data,
            format="multipart",
        )
        self.__validate_update_data(response)

    def test_put_user_profile_missing_name(self):
        """
        Test put user profile missing name
        Expects:
            - The response is a 200 ok
            - The status is ok
            - Name no updated but other data is updated
        """

        # Remove name from data
        new_name = self.update_data.pop("name")

        response = self.client.put(
            self.endpoint,
            self.update_data,
            format="multipart",
        )
        self.__validate_update_data(response, check_name=False)

        self.assertNotEqual(self.profile.name, new_name)

    def test_put_user_profile_missing_avatar(self):
        """
        Test put user profile missing avatar
        Expects:
            - The response is a 200 ok
            - The status is ok
            - Avatar no updated but other data is updated
        """

        # Remove avatar from data
        self.update_data.pop("profile_img")

        response = self.client.put(
            self.endpoint,
            self.update_data,
            format="multipart",
        )
        self.__validate_update_data(response, check_avatar=False)

        self.assertNotIn("new_avatar", self.profile.profile_img.name)

    def test_put_user_profile_missing_password(self):
        """
        Test put user profile missing password
        Expects:
            - The response is a 200 ok
            - The status is ok
            - Password no updated but other data is updated
                (cannot login with new password)
        """

        # Remove password from data
        new_password = self.update_data.pop("password")

        response = self.client.put(
            self.endpoint,
            self.update_data,
            format="multipart",
        )
        self.__validate_update_data(response, check_password=False)

        # Trt to login and confirm error
        self.__validate_login(can_login=False, password=new_password)

    def test_put_user_profile_missing_data(self):
        """
        Test put user profile missing data
        Expects:
            - The response is a 400 BAD REQUEST
            - The status is error
            - The message is invalid_data
        """

        response = self.client.put(
            self.endpoint,
            {},
            format="multipart",
        )

        # valdiate error message
        self.assertEqual(response.data["message"], "Invalid data")
        self.assertIn("fields", response.data["data"])
        self.assertEqual(response.data["data"]["fields"], "no_data")
        
        # Validate data no updated
        self.__validate_data_no_updated(response, check_password=False)

    def test_put_same_password(self):
        """
        Test put user profile, using the same current password
        Expects:
            - The response is a 400 BAD REQUEST
            - The status is error
            - The message is same_pass
        """

        # Use same password
        self.update_data["password"] = self.password
        response = self.client.put(
            self.endpoint,
            self.update_data,
            format="multipart",
        )
        
        # Validate error message
        self.assertEqual(response.data["message"], "Invalid data")
        self.assertIn("password", response.data["data"])
        self.assertEqual(response.data["data"]["password"], "same_pass")

        # Validate data no updated
        self.__validate_data_no_updated(response, check_password=False)
