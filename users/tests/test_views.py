import os
from datetime import timedelta

from django.utils import timezone
from django.conf import settings
from django.core import mail
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile

from rest_framework.response import Response
from rest_framework.test import APITestCase
from rest_framework import status

from users import models
from core.tests_base.test_views import BaseTestApiViewsMethods

from bs4 import BeautifulSoup


class CustomJWTViewTests(APITestCase):

    @classmethod
    def setUpTestData(cls):
        # Create a test user
        cls.username = "testuser"
        cls.password = "testpassword"
        cls.user = User.objects.create_user(
            username="testuser", password="testpassword"
        )

        # Setup endpoints
        cls.token_obtain_url = "/api/token/"
        cls.token_refresh_url = "/api/token/refresh/"

    def test_token_obtain_pair(self):
        """
        Test that a token pair can be obtained with valid credentials
        and that the custom response structure is returned.
        """
        response = self.client.post(
            self.token_obtain_url,
            {"username": self.username, "password": self.password},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("status", response.data)
        self.assertIn("message", response.data)
        self.assertIn("data", response.data)
        self.assertEqual(response.data["status"], "ok")
        self.assertEqual(response.data["message"], "generated")
        self.assertIn("access", response.data["data"])
        self.assertIn("refresh", response.data["data"])

    def test_token_obtain_pair_invalid_credentials(self):
        """
        Test that the API returns a 401 error for invalid credentials.
        """
        response = self.client.post(
            self.token_obtain_url,
            {"username": "wronguser", "password": "wrongpassword"},
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["status"], "error")
        self.assertEqual(
            response.data["message"],
            "La combinación de credenciales no tiene una cuenta activa",
        )
        self.assertNotIn("access", response.data["data"])
        self.assertNotIn("refresh", response.data["data"])

    def test_token_refresh(self):
        """
        Test that an access token can be refreshed using a valid refresh token
        and that the custom response structure is returned.
        """
        # Obtain token pair
        token_response = self.client.post(
            self.token_obtain_url,
            {"username": self.username, "password": self.password},
        )
        refresh_token = token_response.data["data"]["refresh"]

        # Refresh the token
        response = self.client.post(self.token_refresh_url, {"refresh": refresh_token})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("status", response.data)
        self.assertIn("message", response.data)
        self.assertIn("data", response.data)
        self.assertEqual(response.data["status"], "ok")
        self.assertEqual(response.data["message"], "refreshed")
        self.assertIn("access", response.data["data"])

    def test_token_refresh_invalid_token(self):
        """
        Test that the API returns a 401 error for an invalid refresh token.
        """
        response = self.client.post(
            self.token_refresh_url, {"refresh": "invalid_refresh_token"}
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["status"], "error")
        self.assertEqual(response.data["message"], "El token es inválido o ha expirado")
        self.assertNotIn("access", response.data["data"])
        self.assertNotIn("refresh", response.data["data"])


class RegisterViewEmailTestsCase(BaseTestApiViewsMethods):
    """Test activation email behavior in the register view"""

    def setUp(self):
        super().setUp(
            endpoint="/auth/register/",
            restricted_post=False,
        )

        # Get the path to your avatar file
        project_path = settings.BASE_DIR
        avatar_path = os.path.join(project_path, "media", "test", "avatar.png")

        # Open the actual file and create a SimpleUploadedFile
        with open(avatar_path, "rb") as f:
            avatar_file = SimpleUploadedFile(
                name="avatar.png", content=f.read(), content_type="image/png"
            )

        self.data = {
            "username": "test_user_email",
            "password": "testpassword",
            "email": "test_user_email@gmail.com",
            "avatar": avatar_file,
            "last_password": "test last password",
        }

    def test_created_email_sent(self):
        """Test that an email is sent when a user is created"""

        # Submit data as multipart form (required for file uploads)
        response = self.client.post(
            self.endpoint,
            self.data,  # Don't use urlencode for multipart
            format="multipart",  # Use multipart for file uploads
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Validate 1 email sent
        emails_sent = mail.outbox
        self.assertEqual(len(emails_sent), 1)

    def test_created_email_content(self):
        """Test content of the email sent when a user is created

        Expects:
            - An email is sent to the user
            - The email has the correct subject
            - The email has the correct to
            - The email has the correct body
            - The email has the correct link (token)
            - The email has the correct name
        """

        # Submit data as a post html form
        self.client.post(self.endpoint, self.data, format="multipart")

        # Validate general data
        email = mail.outbox[0]
        self.assertEqual(email.subject, "Activate your account")
        self.assertEqual(email.to, [self.data["email"]])
        self.assertIn("/auth/activate/", email.body)
        self.assertIn("Hi " + self.data["username"].replace("_", " "), email.body)

        # Validate activation token
        soup = BeautifulSoup(email.alternatives[0][0], "html.parser")
        activation_token = soup.select_one("a.cta")["href"].split("/")[-2]
        token = models.TempToken.objects.get(token=activation_token)
        self.assertEqual(token.type, "sign_up")
        self.assertEqual(token.profile.user.email, self.data["email"])

    def test_no_created_no_email_sent(self):
        """Test that no email is sent when a user is not created

        Expects:
            - No email is sent
            - The user is not created
            - The response is a 400 bad request
        """

        # Create a user directly in the database
        User.objects.create_user(
            username=self.data["username"],
            password=self.data["password"],
            email=self.data["email"],
        )

        # Submit data as a post html form
        response = self.client.post(self.endpoint, self.data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Validate no email sent
        emails_sent = mail.outbox
        self.assertEqual(len(emails_sent), 0)

    def test_logo_attached(self):
        """Test that the logo is attached to the email"""
        # Submit data as a post html form
        self.client.post(self.endpoint, self.data, format="multipart")

        # Validate 1 email sent
        emails_sent = mail.outbox
        self.assertEqual(len(emails_sent), 1)

        # Validate the logo is attached to the email
        email = mail.outbox[0]
        self.assertIn("cid:logo", email.alternatives[0][0])

        # Validate src of logo
        soup = BeautifulSoup(email.alternatives[0][0], "html.parser")
        logo_src = soup.select_one("img.banner")["src"]
        self.assertIn("cid:logo", logo_src)


class ActivateAccountViewTestsCase(BaseTestApiViewsMethods):
    """Test activation account behavior in the activate account view"""

    def setUp(self):
        super().setUp(
            endpoint="/auth/activate/{token}/",
            restricted_get=False,
        )

        self.data = {
            "username": "test_user_activate",
            "password": "testpassword",
            "email": "test_user_activate@gmail.com",
            "last_password": "test last password",
        }

        # Create user and get sign up token
        self.token = self.__register_default_user()

    def __register_default_user(self) -> str:
        """Register a user

        Returns:
            str: The token of the user
        """

        register_endpoint = "/auth/register/"
        response = self.client.post(register_endpoint, self.data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(email=self.data["email"])
        token = models.TempToken.objects.get(profile__user=user)
        return token.token

    def __validate_token_user(self, token_is_active: bool, user_is_active: bool):
        """Validate that the user is not activated

        Args:
            token_is_active (bool): If the token is active
            user_is_active (bool): If the user is active
        """

        user = User.objects.get(email=self.data["email"])
        self.assertEqual(user.is_active, user_is_active)

        token = models.TempToken.objects.get(token=self.token)
        self.assertEqual(token.is_active, token_is_active)

    def __validate_response_error(self, response: Response):
        """Validate that the response is an error"""
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["status"], "error")
        self.assertEqual(response.data["message"], "Account activation failed.")
        self.assertEqual(response.data["data"]["token"], ["Invalid token."])

    def test_activate_account(self):
        """Test try to activate an account with a valid token

        Expects:
            - The user is activated
            - The token is disabled
            - The response is a 200 OK
        """

        # Validate response
        response = self.client.get(self.endpoint.format(token=self.token))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "ok")
        self.assertEqual(response.data["message"], "Account activated successfully.")

        # Validate token disable and user activated
        self.__validate_token_user(token_is_active=False, user_is_active=True)

    def test_invalid_token(self):
        """Test try to activate an account with an invalid token

        Expects:
            - The user is not activated
            - The token is not disabled
            - The response is a 400 BAD REQUEST
        """

        # Validate response
        response = self.client.get(self.endpoint.format(token="invalid_token"))
        self.__validate_response_error(response)

        # Validate user is not activated and token still active
        self.__validate_token_user(token_is_active=True, user_is_active=False)

    def test_expired_token(self):
        """Test try to activate an account with an expired token

        Expects:
            - The user is not activated
            - The token is not disabled
            - The response is a 400 BAD REQUEST
        """

        # Change created_at to 100 hours ago
        token = models.TempToken.objects.get(token=self.token)
        token.created_at = timezone.now() - timedelta(hours=100)
        token.save()

        # Validate response
        response = self.client.get(self.endpoint.format(token=self.token))
        self.__validate_response_error(response)

        # Validate user is not activated and token still active
        self.__validate_token_user(token_is_active=True, user_is_active=False)

    def test_disabled_token(self):
        """Test try to activate an account with a disabled token

        Expects:
            - The user is not activated
            - The token is not disabled
            - The response is a 400 BAD REQUEST
        """
        
        # Disable token
        token = models.TempToken.objects.get(token=self.token)
        token.is_active = False
        token.save()

        # Validate response
        response = self.client.get(self.endpoint.format(token=self.token))
        self.__validate_response_error(response)

        # Validate user is not activated and token still disabled
        self.__validate_token_user(token_is_active=False, user_is_active=False)
