import re

def is_valid_url(url):
    if not url or not isinstance(url, str):
        return False

    url = url.strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    pattern = re.compile(
        r'^(https?:\/\/)'              
        r'('
        r'(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})'
        r'|'
        r'(\d{1,3}\.){3}\d{1,3}'
        r')'
        r'(:\d+)?'
        r'(\/.*)?$'
    )

    return bool(pattern.match(url))