from core.tests_base.test_admin import TestAdminBase


class ProfileAdminTestCase(TestAdminBase):
    """Testing profile admin"""

    def setUp(self):
        super().setUp()
        self.endpoint = "/admin/jwt_auth/profile/"

    def test_search_bar(self):
        """Validate search bar working"""

        self.submit_search_bar(self.endpoint)


class TempTokenAdminTestCase(TestAdminBase):
    """Testing temp token admin"""

    def setUp(self):
        super().setUp()
        self.endpoint = "/admin/jwt_auth/temptoken/"

    def test_search_bar(self):
        """Validate search bar working"""

        self.submit_search_bar(self.endpoint)
