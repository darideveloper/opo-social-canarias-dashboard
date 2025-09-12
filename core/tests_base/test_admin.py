from time import sleep

from django.http import HttpResponse
from django.test import LiveServerTestCase
from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.common.by import By
from bs4 import BeautifulSoup


class TestAdminBase(TestCase):
    """Base class to test admin"""

    def setUp(self):
        """Load data and create admin user"""

        # Create admin user
        self.admin_user, self.admin_pass, self.admin = self.create_admin_user()

        # Login in client
        self.client.login(username=self.admin_user, password=self.admin_pass)

    def create_admin_user(self) -> tuple[str, str, User]:
        """Create a new admin user and return it

        Returns:
            tuple:
                str: Username of the user created
                str: Password of the user created
                User: User created
        """

        # Create admin user
        password = "admin"
        user = User.objects.create_superuser(
            username="admin",
            email="test@gmail.com",
            password=password,
        )

        return user.username, password, user

    def submit_search_bar(
        self, endpoint: str, search_text: str = "test"
    ) -> HttpResponse:
        """Validate search bar in admin page

        Args:
            endpoint (str): Endpoint to test inside /admin/
            search_text (str): Text to search. Defaults to "test".

        Returns: HttpResponse: Response of the request
        """

        # Fix endpoint prefix if needed
        if not endpoint.startswith("/admin/"):
            endpoint = f"/admin/{endpoint.lstrip('/')}"

        # Get response
        response = self.client.get(f"{endpoint}", {"q": search_text})
        print(f"Testing search bar in {endpoint} with text '{search_text}'")

        # Check if the response is valid
        self.assertEqual(response.status_code, 200)

        # Check if the search text is in the response content
        self.assertContains(response, search_text)

        return response

    def submit_custom_filter(
        self,
        endpoint: str,
        filter_name: str,
        filter_value: str,
        referer_url: str = None,
    ) -> tuple[HttpResponse, str]:
        """Submit custom filter

        Args:
            endpoint (str): Endpoint to test inside /admin/
            filter_name (str): Name of the filter
            filter_value (str): Value of the filter
            referer_url (str): Referer URL to use in the request

        Returns:
            tuple:
                response (HttpResponse): Response of the request
                url (str): URL of the request
        """

        # Get response
        url = f"{endpoint}?{filter_name}={filter_value}"
        response = self.client.get(url, HTTP_REFERER=referer_url)
        message = f"Testing custom filter in {url} with filter"
        message += f" '{filter_name}' and value '{filter_value}'"
        print(message)

        # Check if the response is valid
        self.assertEqual(response.status_code, 200)

        # Check if the filter value is in the response content
        self.assertContains(response, filter_value)

        return response, url

    def get_results_count(self, response: HttpResponse) -> int:
        """Get results count of current page

        Args:
            response (HttpResponse): Response of the request

        Returns: int: Results count
        """

        soup = BeautifulSoup(response.content, "html.parser")

        # Save response intemp html file
        with open("temp.html", "w") as f:
            f.write(soup.prettify())

        # Get results count
        row_selector = "#result_list tbody tr"
        rows = soup.select(row_selector)
        return len(rows)

    def validate_custom_filter(
        self, filter_name: str, filter_value: int, filter_invalid_value: int
    ):
        """Validate custom filter
        Requirements: 2 filters (foreign key) created in database and
        only one of them with results

        Args:
            filter_name (str): Name of the filter
            filter_value (int): Value of the filter
            filter_invalid_value (int): Invalid value of the filter
        """

        # 1rst filter, validate results and filter visible
        response, url = self.submit_custom_filter(
            self.endpoint, filter_name, filter_value
        )
        self.assertGreaterEqual(self.get_results_count(response), 1)
        html_option = f'<option data-name="{filter_name}"'
        html_option += f' value="{filter_value}" selected >'
        self.assertContains(response, html_option)

        # 2nd filter, validate results and filter visible
        referer_url = url
        response, url = self.submit_custom_filter(
            self.endpoint, filter_name, filter_invalid_value, referer_url
        )
        self.assertEqual(self.get_results_count(response), 0)
        html_option = f'<option data-name="{filter_name}"'
        html_option += f' value="{filter_invalid_value}" >'
        self.assertNotContains(response, html_option)

        # Validate no duplicated filter in url
        self.assertNotIn(f"{filter_name}={filter_value}", url)
        self.assertIn(f"{filter_name}={filter_invalid_value}", url)


class TestAdminSeleniumBase(TestAdminBase, LiveServerTestCase):
    """Base class to test admin with selenium (login and setup)"""

    def setUp(self, endpont="/admin/"):
        """Load data, setup and login in each test"""

        # Load data
        # call_command("apps_loaddata")

        # Create admin user
        self.admin_user, self.admin_pass, self.admin = self.create_admin_user()

        # Setup selenium
        self.endpoint = endpont
        self.__setup_selenium__()
        self.__login__()

    def tearDown(self):
        """Close selenium"""
        try:
            self.driver.quit()
        except Exception:
            pass

    def __setup_selenium__(self):
        """Setup and open selenium browser"""
        chrome_options = Options()

        # Run in headless mode if enabled
        if settings.TEST_HEADLESS:
            chrome_options.add_argument("--headless=new")
            chrome_options.add_argument("--disable-gpu")

        # Allow clipboard access
        prefs = {"profile.default_content_setting_values.clipboard": 1}
        chrome_options.add_experimental_option("prefs", prefs)

        # Disable Chrome automation infobars and password save popups
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option("useAutomationExtension", False)
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")

        self.driver = webdriver.Chrome(options=chrome_options)
        self.driver.implicitly_wait(5)

    def __login__(self):

        # Load login page and get fields
        self.driver.get(f"{self.live_server_url}/admin/")
        sleep(2)
        selectors_login = {
            "username": "input[name='username']",
            "password": "input[name='password']",
            "submit": "button[type='submit']",
        }
        fields_login = self.get_selenium_elems(selectors_login)

        fields_login["username"].send_keys(self.admin_user)
        fields_login["password"].send_keys(self.admin_pass)
        fields_login["submit"].click()

        # Wait after login
        sleep(3)

        # Open page
        self.driver.get(f"{self.live_server_url}{self.endpoint}")
        sleep(2)

    def set_page(self, endpoint):
        """Set page"""
        self.driver.get(f"{self.live_server_url}{endpoint}")
        sleep(2)

    def get_selenium_elems(self, selectors: dict) -> dict[str, WebElement]:
        """Get selenium elements from selectors

        Args:
            selectors (dict): css selectors to find: name, value

        Returns:
            dict[str, WebElement]: selenium elements: name, value
        """
        fields = {}
        for key, value in selectors.items():
            try:
                fields[key] = self.driver.find_element(By.CSS_SELECTOR, value)
            except Exception:
                fields[key] = None
        return fields
