from django.contrib.auth.models import User

from rest_framework.test import APITestCase
from rest_framework import status


from core.tests_base.test_admin import TestAdminBase


class BaseTestApiViewsMethods(APITestCase, TestAdminBase):
    """Base class for testing api views that only allows get views"""

    def setUp(
        self,
        endpoint="/api/",
        restricted_get: bool = False,
        restricted_post: bool = True,
        restricted_put: bool = True,
        restricted_patch: bool = True,
        restricted_delete: bool = True,
    ):
        """Initialize test data

        restricted_get (bool): If the get method is restricted
        restricted_post (bool): If the post method is restricted
        restricted_put (bool): If the put method is restricted
        restricted_delete (bool): If the delete method is restricted
        """

        # Create user and login
        username = "test_user"
        password = "test_pass"
        User.objects.create_superuser(
            username=username,
            email="test@gmail.com",
            password=password,
        )
        self.client.login(username=username, password=password)

        # Save data
        self.endpoint = endpoint
        self.restricted_get = restricted_get
        self.restricted_post = restricted_post
        self.restricted_put = restricted_put
        self.restricted_patch = restricted_patch
        self.restricted_delete = restricted_delete

    def validate_invalid_method(self, method: str):
        """Validate that the given method is not allowed on the endpoint"""
        
        if self.endpoint == "/api/":
            return

        endpoint = self.endpoint
        if not endpoint.endswith("/"):
            endpoint += "/"

        response = getattr(self.client, method)(endpoint)
        self.assertEqual(
            response.status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
            f"'{method}' - '{self.endpoint}' should be restricted",
        )
        print(f"{method} - {self.endpoint} restricted - ok")

    def test_authenticated_user_post(self):
        """Test that authenticated users can not post to the endpoint"""

        if self.restricted_post:
            self.validate_invalid_method("post")

    def test_authenticated_user_put(self):
        """Test that authenticated users can not put to the endpoint"""

        if self.restricted_put:
            self.validate_invalid_method("put")

    def test_authenticated_user_patch(self):
        """Test that authenticated users can not patch to the endpoint"""

        if self.restricted_patch:
            self.validate_invalid_method("patch")

    def test_authenticated_user_delete(self):
        """Test that authenticated users can not delete to the endpoint"""

        if self.restricted_delete:
            self.validate_invalid_method("delete")

    def test_unauthenticated_user_get(self):
        """Test that unauthenticated users can not get to the endpoint"""

        if self.restricted_get:
            self.validate_invalid_method("get")