from bs4 import BeautifulSoup
import requests

def indieauth_callback_handler(
        code,
        state,
        token_endpoint,
        code_verifier,
        session_state,
        me,
        callback_url,
        client_id,
        required_scopes
    ):
    if state != session_state:
        message = "Your authentication failed. Please try again."
        return message, None

    data = {
        "code": code,
        "redirect_uri": callback_url,
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code_verifier": code_verifier
    }

    headers = {
        "Accept": "application/json"
    }

    r = requests.post(token_endpoint, data=data, headers=headers)
    
    if r.status_code != 200:
        message = "There was an error with your token endpoint server."
        return message, None

    # remove code verifier from session because the authentication flow has finished

    if me != None:
        if r.json().get("me").strip("/") != me.strip("/"):
            message = "Your domain is not allowed to access this website."
        return message, None

    granted_scopes = r.json().get("scope").split(" ")

    if r.json().get("scope") == "" or any(scope not in granted_scopes for scope in required_scopes):
        message = "You need to grant 'read' and 'channels' access to use this tool."
        return message, None

    return None, r.json()

def discover_endpoints(domain, headers_to_find):
    response = {}

    r = requests.get(domain)

    http_link_headers = r.headers.get("link")

    if http_link_headers:
        parsed_link_headers = requests.utils.parse_header_links(http_link_headers.rstrip('>').replace('>,<', ',<'))
    else:
        parsed_link_headers = []

    for h in parsed_link_headers:
        if h["rel"] in headers_to_find:
            response[h["rel"]] = h["url"]

    soup = BeautifulSoup(r.text, "html.parser")

    for link in soup.find_all("link"):
        if link.get("rel") in headers_to_find:
            response[link.get("rel")] = link.get("href")

    for url in response.keys():
        if not response[url].startswith("https://") and not response[url].startswith("http://"):
            response.pop(url)

    return response