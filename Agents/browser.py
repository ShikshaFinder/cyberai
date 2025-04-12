import json
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from agent import Agent
import os
import time
import logging

class Browser(Agent):
    def __init__(self, api_key, azure_endpoint=None, deployment_name=None):
        super().__init__("Browser", api_key, azure_endpoint, deployment_name)
        self.com_file = "com.json"
        self.driver = None
        self.environment_requirements = {
            "auth_tokens": [],
            "external_services": []
        }
        self.setup_logging()

    def setup_logging(self):
        """Setup logging for browser operations"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('browser_agent.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('BrowserAgent')

    def initialize_driver(self):
        """Initialize the undetected-chromedriver"""
        try:
            options = uc.ChromeOptions()
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--disable-extensions')
            options.add_argument('--disable-popup-blocking')
            
            self.driver = uc.Chrome(options=options)
            self.driver.set_page_load_timeout(30)
            self.logger.info("Browser driver initialized successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize browser driver: {str(e)}")
            return False

    def read_communication(self):
        """Read communication from com.json file"""
        if os.path.exists(self.com_file):
            try:
                with open(self.com_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {}
        return {}

    def write_communication(self, data):
        """Write communication to com.json file"""
        with open(self.com_file, 'w') as f:
            json.dump(data, f, indent=2)

    def check_environment_requirements(self):
        """Check if all environment requirements are met"""
        missing_requirements = []
        
        # Check auth tokens
        for token in self.environment_requirements["auth_tokens"]:
            if not os.getenv(token):
                missing_requirements.append({
                    "type": "auth_token",
                    "name": token,
                    "description": f"Authentication token for {token} is required"
                })
        
        # Check external services
        for service in self.environment_requirements["external_services"]:
            if not os.getenv(service):
                missing_requirements.append({
                    "type": "external_service",
                    "name": service,
                    "description": f"External service {service} is required"
                })
        
        return missing_requirements

    def request_additional_info(self, message):
        """Request additional information through com.json"""
        # First check environment requirements
        missing_requirements = self.check_environment_requirements()
        if missing_requirements:
            communication = {
                "agent": "Browser",
                "request": {
                    "type": "environment_requirements",
                    "context": "Missing environment requirements",
                    "details": {
                        "missing_requirements": missing_requirements
                    }
                },
                "timestamp": time.time()
            }
            self.write_communication(communication)
            response = self.read_communication()
            
            # If environment requirements are provided in response, update environment
            if response and "environment" in response:
                env_data = response["environment"]
                for token in env_data.get("auth_tokens", {}):
                    os.environ[token] = env_data["auth_tokens"][token]
                for service in env_data.get("external_requirements", {}):
                    os.environ[service] = env_data["external_requirements"][service]
            
            # Recheck requirements after potential updates
            missing_requirements = self.check_environment_requirements()
            if missing_requirements:
                return None

        # If all requirements are met, proceed with the original request
        communication = {
            "agent": "Browser",
            "request": {
                "type": "additional_info",
                "context": message.get("context", ""),
                "details": message
            },
            "timestamp": time.time()
        }
        self.write_communication(communication)
        return self.read_communication()

    def navigate_to_url(self, url):
        """Navigate to a specific URL"""
        try:
            self.driver.get(url)
            self.logger.info(f"Successfully navigated to {url}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to navigate to {url}: {str(e)}")
            return False

    def find_element(self, by, value, timeout=10):
        """Find an element on the page with timeout"""
        try:
            element = WebDriverWait(self.driver, timeout).until(
                EC.presence_of_element_located((by, value))
            )
            return element
        except TimeoutException:
            self.logger.warning(f"Timeout waiting for element {value}")
            return None

    def perform_search(self, query, search_engine="google"):
        """Perform a web search"""
        try:
            if search_engine.lower() == "google":
                self.navigate_to_url("https://www.google.com")
                search_box = self.find_element(By.NAME, "q")
                if search_box:
                    search_box.send_keys(query)
                    search_box.submit()
                    self.logger.info(f"Performed search for: {query}")
                    return True
            return False
        except Exception as e:
            self.logger.error(f"Search failed: {str(e)}")
            return False

    def extract_information(self, target_url, requirements):
        """Extract specific information from a webpage"""
        try:
            if not self.navigate_to_url(target_url):
                return None

            extracted_data = {}
            for requirement in requirements:
                element = self.find_element(
                    By.CSS_SELECTOR if requirement.get("css_selector") else By.XPATH,
                    requirement.get("css_selector") or requirement.get("xpath")
                )
                if element:
                    extracted_data[requirement["name"]] = element.text

            self.logger.info(f"Successfully extracted information from {target_url}")
            return extracted_data
        except Exception as e:
            self.logger.error(f"Failed to extract information: {str(e)}")
            return None

    def assist_other_agents(self, request):
        """Assist other agents with web-based tasks"""
        try:
            if not self.driver:
                if not self.initialize_driver():
                    return None

            task_type = request.get("type")
            if task_type == "search":
                return self.perform_search(request.get("query"), request.get("search_engine"))
            elif task_type == "extract":
                return self.extract_information(request.get("url"), request.get("requirements"))
            else:
                self.logger.warning(f"Unknown task type: {task_type}")
                return None
        except Exception as e:
            self.logger.error(f"Failed to assist with task: {str(e)}")
            return None

    def close(self):
        """Close the browser and cleanup"""
        try:
            if self.driver:
                self.driver.quit()
                self.driver = None
                self.logger.info("Browser closed successfully")
        except Exception as e:
            self.logger.error(f"Error closing browser: {str(e)}")

    def __del__(self):
        """Destructor to ensure browser is closed"""
        self.close() 