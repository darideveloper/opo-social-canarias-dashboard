import os

from django.conf import settings
from django.core import mail
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile

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
        with open(avatar_path, 'rb') as f:
            avatar_file = SimpleUploadedFile(
                name="avatar.png",
                content=f.read(),
                content_type="image/png"
            )

        self.data = {
            "username": "test_user_email",
            "password": "testpassword",
            "email": "test@gmail.com",
            "avatar": avatar_file,
            "last_password": "test last password",
        }

    def test_created_email_sent(self):
        """Test that an email is sent when a user is created"""
        
        # Submit data as multipart form (required for file uploads)
        response = self.client.post(
            self.endpoint,
            self.data,  # Don't use urlencode for multipart
            format='multipart'  # Use multipart for file uploads
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
        self.client.post(
            self.endpoint,
            self.data,
            format='multipart'
        )

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
        response = self.client.post(
            self.endpoint,
            self.data,
            format='multipart'
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Validate no email sent
        emails_sent = mail.outbox
        self.assertEqual(len(emails_sent), 0)
        
    def test_logo_attached(self):
        """Test that the logo is attached to the email"""
        # Submit data as a post html form
        self.client.post(
            self.endpoint,
            self.data,
            format='multipart'
        )
        
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