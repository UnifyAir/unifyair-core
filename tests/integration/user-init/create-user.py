import requests
import yaml
import argparse
from urllib.parse import urljoin
import logging

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)
logger = logging.getLogger(__name__)

# The raw curl request for login is:
# 
# curl 'http://0.0.0.0:5001/api/login' \
#   -H 'Accept: application/json, text/plain, */*' \
#   -H 'Accept-Language: en-GB,en-US;q=0.9,en;q=0.8' \
#   -H 'Connection: keep-alive' \
#   -H 'Content-Type: application/json' \
#   -H 'DNT: 1' \
#   -H 'Origin: http://0.0.0.0:5001' \
#   -H 'Referer: http://0.0.0.0:5001/login' \
#   --data-raw '{"username":"admin","password":"free5gc"}' \
#   --insecure

def get_token(username: str, password: str, api_url: str) -> str:
    """
    Authenticate with the API using the provided credentials and return a JWT token.
    
    Parameters:
        username (str): Username for authentication.
        password (str): Password for authentication.
        api_url (str): URL of the login API endpoint.
    
    Returns:
        str: JWT token obtained upon successful authentication.
    
    Raises:
        Exception: If authentication fails or the token is missing from the response.
    """
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
    }
    payload = {
        'username': username,
        'password': password,
    }
    logger.info(f"Sending POST request to {api_url} with payload: {payload}")
    try:
        response = requests.post(api_url, headers=headers, json=payload, verify=False)
        logger.info(f"Received response: {response.status_code} {response.text}")
        response.raise_for_status()
        data = response.json()

        # Adjust this according to your API's response structure
        token = data.get('token') or data.get('access_token')
        if not token:
            logger.error(f"Token not found in response: {data}")
            raise Exception(f"Token not found in response: {data}")

        return token
    except Exception as e:
        logger.error(f"Error during authentication: {e}")
        raise


def create_subscriber(token: str, subscriber_data: dict, api_url: str) -> requests.Response:
    """
    Send a POST request to create a subscriber using the specified API URL and authentication token.
    
    Parameters:
        token (str): JWT token used for API authentication.
        subscriber_data (dict): Dictionary containing subscriber details to be sent as JSON.
        api_url (str): Endpoint URL for subscriber creation.
    
    Returns:
        requests.Response: The HTTP response object from the API.
    """
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
        'Token': token,
    }
    logger.info(f"Sending POST request to {api_url} with payload: {subscriber_data}")
    try:
        response = requests.post(api_url, headers=headers, json=subscriber_data, verify=False)
        logger.info(f"Received response: {response.status_code} {response.text}")
        response.raise_for_status()
        return response
    except Exception as e:
        logger.error(f"Error creating subscriber at {api_url}: {e}")
        raise


def create_subscribers_from_yaml(token: str, config: dict, api_url_template: str):
    """
    Creates subscriber entries via the API for each user defined in the provided configuration dictionary.
    
    Iterates over the list of users in the config, formatting the API URL for each using their `ueId` and `plmnID`. Skips users missing required identifiers and logs a warning. Calls the subscriber creation API for each valid user and logs the result.
    """
    users = config.get('users', [])
    for user in users:
        ueId = user.get('ueId')
        plmnID = user.get('plmnID')
        if not ueId or not plmnID:
            logger.warning(f"Skipping user missing ueId or plmnID: {user}")
            continue
        api_url = api_url_template.format(ueId=ueId, plmnID=plmnID)
        try:
            resp = create_subscriber(token, user, api_url)
            logger.info(f"Created subscriber {ueId}: {resp.status_code}")
        except Exception as e:
            logger.error(f"Failed to create subscriber {ueId}: {e}")


def load_config(yaml_path: str):
    """
    Load and parse a YAML configuration file from the specified path.
    
    Parameters:
        yaml_path (str): Path to the YAML file to be loaded.
    
    Returns:
        dict: Parsed contents of the YAML file as a Python dictionary.
    """
    with open(yaml_path, 'r') as f:
        return yaml.safe_load(f)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create WebUI users and subscribers from a YAML config file.")
    parser.add_argument(
        "-c", "--config",
        help="Path to the YAML config file (default: webui-user-config.yaml)"
    )
    args = parser.parse_args()
    yaml_path = args.config
    config = load_config(yaml_path)
    login_creds = config.get('login-creds', {})
    username = login_creds.get('username')
    password = login_creds.get('password')
    webui_url = config.get('webui-url')
    if not username or not password:
        logger.error("Username or password missing in 'login-creds' section of YAML config.")
        raise Exception("Username or password missing in 'login-creds' section of YAML config.")
    if not webui_url:
        logger.error("'webui-url' missing in YAML config.")
        raise Exception("'webui-url' missing in YAML config.")
    login_api_url = urljoin(webui_url, 'api/login')
    token = get_token(username, password, login_api_url)
    logger.info(f"Obtained token: {token}")

    # API endpoint template
    subscriber_api_template = urljoin(webui_url, 'api/subscriber/{ueId}/{plmnID}')
    create_subscribers_from_yaml(token, config, subscriber_api_template)
