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

from jwt_auth import models
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
        cls.token_obtain_url = "/auth/token/"
        cls.token_refresh_url = "/auth/token/refresh/"

    def test_token_obtain_pair(self):
        """
        Test that a token pair can be obtained with valid credentials
        and that the custom response structure is returned with HttpOnly cookies.
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
        
        # Check that tokens are set as HttpOnly cookies
        self.assertIn('access_token', response.cookies)
        self.assertIn('refresh_token', response.cookies)
        self.assertTrue(response.cookies['access_token'].value)
        self.assertTrue(response.cookies['refresh_token'].value)

    def test_token_obtain_pair_invalid_credentials(self):
        """
        Test that the API returns a 401 error for invalid credentials
        and that no cookies are set.
        """
        response = self.client.post(
            self.token_obtain_url,
            {"username": "wronguser", "password": "wrongpassword"},
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["status"], "error")
        
        # Check that no tokens are set as cookies for invalid credentials
        self.assertNotIn('access_token', response.cookies)
        self.assertNotIn('refresh_token', response.cookies)

    def test_token_refresh(self):
        """
        Test that an access token can be refreshed using a valid refresh token
        from cookies and that the custom response structure is returned.
        """
        # Obtain token pair (tokens will be set as cookies)
        token_response = self.client.post(
            self.token_obtain_url,
            {"username": self.username, "password": self.password},
        )
        self.assertEqual(token_response.status_code, status.HTTP_200_OK)
        
        # Refresh the token (using cookies from previous response)
        response = self.client.post(self.token_refresh_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("status", response.data)
        self.assertIn("message", response.data)
        self.assertIn("data", response.data)
        self.assertEqual(response.data["status"], "ok")
        self.assertEqual(response.data["message"], "refreshed")
        
        # Check that a new access token cookie is set
        self.assertIn('access_token', response.cookies)
        self.assertTrue(response.cookies['access_token'].value)

    def test_token_refresh_invalid_token(self):
        """
        Test that the API returns a 401 error for an invalid refresh token cookie.
        """
        # Set an invalid refresh token cookie
        self.client.cookies['refresh_token'] = 'invalid_refresh_token'
        
        response = self.client.post(self.token_refresh_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["status"], "error")
        
    def test_token_refresh_missing_token(self):
        """
        Test that the API returns a 400 error when no refresh token cookie is present.
        """
        response = self.client.post(self.token_refresh_url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["status"], "error")
        self.assertEqual(response.data["message"], "refresh_token_missing")


class RegisterBaseTestsCase(BaseTestApiViewsMethods):
    """
    Test activation email behavior in the register view
    """

    def setUp(self):
        super().setUp(
            endpoint="/auth/register/",
            restricted_post=False,
        )

        # Additional apis
        self.token_obtain_url = "/auth/token/"

        # Get default data
        self.data = self.get_data()

    def get_data(
        self,
        name: str = "Sample name",
        password: str = "testpassword",
        email: str = "test_user_email@gmail.com",
        avatar_file_name: str = "avatar.png",
    ) -> dict:
        """
        Get data for register

        Returns:
            dict: Data for register
                - name: str
                - password: str
                - email: str
                - avatar: SimpleUploadedFile
                - last_password: str
        """

        # Get the path to your avatar file
        project_path = settings.BASE_DIR
        avatar_path = os.path.join(project_path, "media", "test", avatar_file_name)

        # Open the actual file and create a SimpleUploadedFile
        with open(avatar_path, "rb") as f:
            avatar_file = SimpleUploadedFile(
                name="avatar.png", content=f.read(), content_type="image/png"
            )

        # Data formatted data
        return {
            "name": name,
            "password": password,
            "email": email,
            "avatar": avatar_file,
        }


class RegisterUserTestCase(RegisterBaseTestsCase):
    """Test user creation behavior"""

    def test_create_user(self):
        """
        Test that a user is created

        Expects:
            - A user is created
            - The response is a 201 CREATED
            - The response data has the correct email
            - User created
            - Avatar is attached to the user
        """

        # Submit data as multipart form (required for file uploads)
        response = self.client.post(
            self.endpoint,
            self.data,  # Don't use urlencode for multipart
            format="multipart",  # Use multipart for file uploads
        )

        # Validate user created correctly
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Validate response data
        response_data = response.data
        self.assertEqual(response_data["status"], "ok")
        self.assertEqual(response_data["message"], "account_created")
        self.assertEqual(response_data["data"]["email"], self.data["email"])

        # Valdiate user created and has correct username
        user = User.objects.get(email=self.data["email"])
        self.assertEqual(user.username, self.data["email"])

        # Validate avatar is attached
        self.assertNotEqual(user.profile.profile_img.name, "")

    def test_create_user_without_avatar(self):
        """
        Test that a user is created even if there's no avatar

        Expects:
            - A user is created
            - The response is a 201 CREATED
            - The response data has the correct email
            - User created
            - Avatar is not attached to the user
        """

        del self.data["avatar"]

        # Submit data as multipart form (required for file uploads) without avatar
        response = self.client.post(
            self.endpoint,
            self.data,  # Don't use urlencode for multipart
            format="multipart",  # Use multipart for file uploads
        )

        # Validate user created correctly
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Validate response data
        response_data = response.data
        self.assertEqual(response_data["status"], "ok")
        self.assertEqual(response_data["message"], "account_created")
        self.assertEqual(response_data["data"]["email"], self.data["email"])

        # Validate user created and has correct username
        user = User.objects.get(email=self.data["email"])
        self.assertEqual(user.username, self.data["email"])

        # Validate avatar is not attached
        self.assertEqual(user.profile.profile_img.name, "")

    def test_create_user_missing_info(self):
        """
        Test that an error is received when there's missing required fields
        (missing name)

        Expects:
            - An error is received when there's missing required fields (missing name)
            - The response is a 400 BAD REQUEST
            - The error message is "Invalid data"
            - The error message has the required fields
            - User is not created
        """

        del self.data["name"]

        # Submit data as multipart form (required for file uploads)
        response = self.client.post(
            self.endpoint,
            self.data,  # Don't use urlencode for multipart
            format="multipart",  # Use multipart for file uploads
        )

        # Validate user is not created
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Validata response data
        response_data = response.data
        self.assertEqual(response_data["status"], "error")
        self.assertEqual(response_data["message"], "invalid_data")
        self.assertIn("name", response_data["data"])

        # Validate user is not created
        user = User.objects.filter(email=self.data["email"])
        self.assertFalse(user.exists())

    def test_create_user_no_info(self):
        """
        Test that an error is received when there's no data

        Expects:
            - An error is received when there's no data
            - The response is a 400 BAD REQUEST
            - The error message is "Invalid data"
            - The error message has the required fields
            - User is not created
        """

        # Submit data as multipart form (required for file uploads)
        # Submit empty data
        response = self.client.post(
            self.endpoint,
            {},  # Don't use urlencode for multipart
            format="multipart",  # Use multipart for file uploads
        )

        # Validate user is not created
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Validata response data
        response_data = response.data
        self.assertEqual(response_data["status"], "error")
        self.assertEqual(response_data["message"], "invalid_data")
        self.assertIn("name", response_data["data"])
        self.assertIn("password", response_data["data"])
        self.assertIn("email", response_data["data"])

        # Validate user is not created
        user = User.objects.filter(email=self.data["email"])
        self.assertFalse(user.exists())

    def test_create_user_with_existing_email(self):
        """
        Test that an error is received when a user with an existing email is created

        Expects:
            - An error is received when a user with an existing email is created
            - The response is a 400 BAD REQUEST
            - The error message is "User with this email already exists."
            - The error message has the "email" field
            - User is not duplicated
        """

        # Create a user with the same email
        email = self.data["email"]
        User.objects.create_user(
            username=email,
            password="testpassword",
            email=email,
        )

        # Submit data as multipart form (required for file uploads)
        response = self.client.post(
            self.endpoint,
            self.data,
            format="multipart",
        )

        # Validate user is not created
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Validate error message
        self.assertEqual(response.data["status"], "error")
        self.assertEqual(response.data["message"], "invalid_data")
        self.assertIn("duplicated_email", str(response.data["data"]["email"]))

        # Validate user is not created
        users = User.objects.filter(email=self.data["email"])
        self.assertEqual(users.count(), 1)
        
    def test_create_user_with_existing_username(self):
        """
        Test that an error is received when a user with an existing username is created

        Expects:
            - An error is received when a user with an existing email is created
            - The response is a 400 BAD REQUEST
            - The error message is "User with this email already exists."
            - The error message has the "email" field
            - User is not duplicated
        """

        # Create a user with the same email
        email = self.data["email"]
        User.objects.create_user(
            username=email,
            password="testpassword",
            # email=email, - email is not required for edge validation
        )

        # Submit data as multipart form (required for file uploads)
        response = self.client.post(
            self.endpoint,
            self.data,
            format="multipart",
        )

        # Validate user is not created
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Validate error message
        self.assertEqual(response.data["status"], "error")
        self.assertEqual(response.data["message"], "invalid_data")
        self.assertIn("duplicated_email", str(response.data["data"]["email"]))

        # Validate user is not created
        users = User.objects.filter(username=self.data["email"])
        self.assertEqual(users.count(), 1)

    def test_login_after_register(self):
        """
        Test that a user can login after registering
        """

        # Submit data as multipart form (required for file uploads)
        response = self.client.post(self.endpoint, self.data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Simulate account activation
        user = User.objects.get(email=self.data["email"])
        user.is_active = True
        user.save()

        # Validate user can login with jwt libs
        response = self.client.post(
            self.token_obtain_url,
            {"username": self.data["email"], "password": self.data["password"]},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_register_second_time(self):
        """
        Test that a user can register again after registering (overwrite user)
        if the account is not active

        Expects:
            - A user is created
            - The response is a 201 CREATED
            - The response data has the correct email
            - User created
            - Avatar is attached to the user
        """

        # Submit data as multipart form (required for file uploads)
        response = self.client.post(self.endpoint, self.data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Second register with diferent data (but keep email)
        new_data = self.get_data(
            name="New name", password="newpassword", avatar_file_name="new_avatar.png"
        )
        response = self.client.post(self.endpoint, new_data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Validate user is overwritten
        user = User.objects.get(email=self.data["email"])
        self.assertEqual(user.username, self.data["email"])

        # Validate user and profile in database
        users = User.objects.filter(email=self.data["email"])
        self.assertEqual(users.count(), 1)
        
        # Validate second register data
        user.profile.refresh_from_db()
        self.assertEqual(user.profile.name, new_data["name"])


class RegisterViewEmailTestsCase(RegisterBaseTestsCase):
    """
    Test activation email behavior in the register view
    """

    def test_created_email_sent(self):
        """
        Test that an email is sent when a user is created

        Expects:
            - An email is sent to the user
            - The email has the correct subject
            - The email has the correct to
            - The email has the correct body
            - The email has the correct link (token)
            - The email has the correct name
        """

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
        """
        Test content of the email sent when a user is created

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
        self.assertIn(settings.FRONTEND_URL, email.body)
        self.assertIn("Hi " + self.data["name"], email.body)

        # Validate activation token
        soup = BeautifulSoup(email.alternatives[0][0], "html.parser")
        activation_token = soup.select_one("a.cta")["href"].split("/")[-2]
        token = models.TempToken.objects.get(token=activation_token)
        self.assertEqual(token.type, "sign_up")
        self.assertEqual(token.profile.user.email, self.data["email"])

    def test_no_created_no_email_sent(self):
        """
        Test that no email is sent when a user is not created

        Expects:
            - No email is sent
            - The user is not created
            - The response is a 400 bad request
        """

        # Create a user directly in the database
        User.objects.create_user(
            username=self.data["email"],
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
        """
        Test that the logo is attached to the email

        Expects:
            - The logo is attached to the email
            - The src of the logo is correct
        """

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
    """
    Test activation account behavior in the activate account view
    """

    def setUp(self):
        super().setUp(
            endpoint="/auth/activate/",
            restricted_post=False,
        )

        self.data = {
            "password": "testpassword",
            "email": "test_user_activate@gmail.com",
            "name": "Test User Activate",
        }

        # Create user and get sign up token
        self.token = self.__register_default_user()

        # Setup endpoints
        self.token_obtain_url = "/auth/token/"

    def __register_default_user(self) -> str:
        """
        Register a user and return the token

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
        """
        Validate that the user is not activated

        Args:
            token_is_active (bool): If the token is active
            user_is_active (bool): If the user is active
        """

        user = User.objects.get(email=self.data["email"])
        self.assertEqual(user.is_active, user_is_active)

        token = models.TempToken.objects.get(token=self.token)
        self.assertEqual(token.is_active, token_is_active)

    def __validate_response_error(self, response: Response):
        """
        Validate that the response is an error

        Args:
            response (Response): The response to validate
        """

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["status"], "error")
        self.assertEqual(response.data["message"], "account_activation_failed")
        self.assertEqual(response.data["data"]["token"], ["Invalid token."])

    def test_activate_account(self):
        """
        Test try to activate an account with a valid token

        Expects:
            - The user is activated
            - The token is disabled
            - The response is a 200 OK
        """

        # Validate response
        response = self.client.post(self.endpoint, {"token": self.token}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "ok")
        self.assertEqual(response.data["message"], "account_activated")

        # Validate token disable and user activated
        self.__validate_token_user(token_is_active=False, user_is_active=True)

        # Validate use can login with jwt
        response = self.client.post(
            self.token_obtain_url,
            {"username": self.data["email"], "password": self.data["password"]},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_invalid_token(self):
        """
        Test try to activate an account with an invalid token

        Expects:
            - The user is not activated
            - The token is not disabled
            - The response is a 400 BAD REQUEST
        """

        # Validate response
        response = self.client.post(
            self.endpoint, {"token": "invalid_token"}, format="json"
        )
        self.__validate_response_error(response)

        # Validate user is not activated and token still active
        self.__validate_token_user(token_is_active=True, user_is_active=False)

    def test_expired_token(self):
        """
        Test try to activate an account with an expired token

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
        response = self.client.post(self.endpoint, {"token": self.token}, format="json")
        self.__validate_response_error(response)

        # Validate user is not activated and token still active
        self.__validate_token_user(token_is_active=True, user_is_active=False)

    def test_disabled_token(self):
        """
        Test try to activate an account with a disabled token

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
        response = self.client.post(self.endpoint, {"token": self.token}, format="json")
        self.__validate_response_error(response)

        # Validate user is not activated and token still disabled
        self.__validate_token_user(token_is_active=False, user_is_active=False)


class ResetPasswordViewTestsCase(BaseTestApiViewsMethods):
    """
    Test password reset functionality:
    - POST: Request password recovery by email (with token)
    - PUT: Reset password by token
    """

    def setUp(self):
        super().setUp(
            endpoint="/auth/password/reset/",
            restricted_post=False,
            restricted_put=False,
        )

        # Create user directly in the database
        self.email = "test_user_reset@gmail.com"
        self.user = User.objects.create_user(
            username=self.email,
            password="testpassword",
            email=self.email,
        )

        # Create profile directly in the database
        self.profile = models.Profile.objects.create(
            user=self.user,
            name="Test User Reset",
        )

        # Create reset password token for PUT tests
        self.token = models.TempToken.objects.create(
            profile=self.profile,
            token="test_token",
            type="pass",
        )

        # Setup endpoints
        self.token_obtain_url = "/auth/token/"

    def __validate_no_email_sent(self):
        """
        Validate that no email is sent
        """
        mails = mail.outbox
        self.assertEqual(len(mails), 0)

    def __validate_post_error_response(self, response: Response):
        """
        Validate that the POST response is an error

        Args:
            response (Response): The response to validate
        """
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["status"], "error")
        self.assertEqual(response.data["message"], "error_sending_recovery_email")
        self.assertIn("email", response.data["data"])

    def __validate_put_error_response(self, response: Response):
        """
        Validate that the PUT response is an error

        Args:
            response (Response): The response to validate
        """
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["status"], "error")
        self.assertEqual(response.data["message"], "error_resetting_password")

    # POST Tests (Password Recovery Request)

    def test_post_recover_password(self):
        """
        Test recover password

        Expects:
            - The email is sent
            - The response is a 200 OK
            - The status is ok
            - The message is recovery_email_sent
            - The data contains the email
        """
        # Delete previous tokens
        models.TempToken.objects.filter(profile=self.profile, type="pass").delete()

        # Submit data as a post json
        response = self.client.post(self.endpoint, {"email": self.email})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "ok")
        self.assertEqual(response.data["message"], "recovery_email_sent")
        self.assertEqual(response.data["data"]["email"], self.email)

        # Validate email sent
        mails = mail.outbox

        # Check email main data
        self.assertEqual(len(mails), 1)
        self.assertEqual(mails[0].to, [self.email])
        self.assertEqual(mails[0].subject, "Recover your password")

        # Validate email recover link and token
        recover_token = models.TempToken.objects.get(
            profile=self.profile, type="pass"
        ).token
        soup = BeautifulSoup(mails[0].alternatives[0][0], "html.parser")
        recover_link = soup.select_one("a.cta")["href"]
        self.assertIn("/auth/reset/", recover_link)
        self.assertIn(recover_token, recover_link)
        self.assertIn(settings.FRONTEND_URL, recover_link)

    def test_post_invalid_email(self):
        """
        Test recover password with an invalid email

        Expects:
            - The response is a 400 BAD REQUEST
            - The status is error
            - The message is error_sending_recovery_email
            - The data contains email error
        """
        # Submit data as a post json
        response = self.client.post(self.endpoint, {"email": "invalid_email@gmail.com"})
        self.__validate_post_error_response(response)

        # Validate no email sent
        self.__validate_no_email_sent()

    def test_post_missing_data(self):
        """
        Test recover password with missing data

        Expects:
            - The response is a 400 BAD REQUEST
            - The status is error
            - The message is error_sending_recovery_email
            - The data contains email error
        """
        # Submit data as a post json
        response = self.client.post(self.endpoint, {})
        self.__validate_post_error_response(response)

        # Validate no email sent
        self.__validate_no_email_sent()

        # Validate required fields in response
        self.assertIn("email", response.data["data"])

    # PUT Tests (Password Reset)

    def test_put_reset_password(self):
        """
        Test reset password

        Expects:
            - The user password is reset
            - The token is disabled
            - The response is a 200 OK
        """
        # Submit data as a put json
        new_password = "new_password"
        response = self.client.put(
            self.endpoint,
            {"token": self.token.token, "new_password": new_password},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "ok")
        self.assertEqual(response.data["message"], "password_reset")
        self.assertEqual(response.data["data"], {})

        # Validate user password
        user = User.objects.get(email=self.profile.user.email)
        self.assertTrue(user.check_password(new_password))

        # Validate token is disabled
        self.token.refresh_from_db()
        self.assertFalse(self.token.is_active)

        # Validate user is active (can login)
        response = self.client.post(
            self.token_obtain_url,
            {"username": self.profile.user.email, "password": new_password},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_invalid_token(self):
        """
        Test reset password with an invalid token

        Expects:
            - The user password is not reset
            - The token is not disabled
            - The response is a 400 BAD REQUEST
        """
        # Submit data as a put json
        new_password = "new_password"
        response = self.client.put(
            self.endpoint,
            {"token": "invalid_token", "new_password": new_password},
            format="json",
        )
        self.__validate_put_error_response(response)

        # Validate real token is active
        self.token.refresh_from_db()
        self.assertTrue(self.token.is_active)

    def test_put_expired_token(self):
        """
        Test reset password with an expired token

        Expects:
            - The user password is not reset
            - The token is not disabled
            - The response is a 400 BAD REQUEST
        """
        # Change created_at to 100 hours ago
        token = models.TempToken.objects.get(token=self.token.token)
        token.created_at = timezone.now() - timedelta(hours=100)
        token.save()

        # Submit data as a put json
        new_password = "new_password"
        response = self.client.put(
            self.endpoint,
            {"token": self.token.token, "new_password": new_password},
            format="json",
        )
        self.__validate_put_error_response(response)

        # Validate token is active (expired but not used)
        self.token.refresh_from_db()
        self.assertTrue(self.token.is_active)

    def test_put_disabled_token(self):
        """
        Test reset password with a disabled token

        Expects:
            - The user password is not reset
            - The token is not disabled
            - The response is a 400 BAD REQUEST
        """
        # Disable token
        token = models.TempToken.objects.get(token=self.token.token)
        token.is_active = False
        token.save()

        # Submit data as a put json
        new_password = "new_password"
        response = self.client.put(
            self.endpoint,
            {"token": self.token.token, "new_password": new_password},
            format="json",
        )
        self.__validate_put_error_response(response)

        # Validate token still disabled
        self.token.refresh_from_db()
        self.assertFalse(self.token.is_active)

    def test_put_missing_data(self):
        """
        Test reset password with missing data

        Expects:
            - The response is a 400 BAD REQUEST
            - The status is error
            - The message is error_resetting_password
        """
        # Submit data as a put json
        response = self.client.put(self.endpoint, {}, format="json")
        self.__validate_put_error_response(response)

        # Validate required fields in response
        self.assertIn("token", response.data["data"])
        self.assertIn("new_password", response.data["data"])

        # Validate token is active (unused)
        self.token.refresh_from_db()
        self.assertTrue(self.token.is_active)
