from os import path
from urllib.parse import urlparse

def url(base, other) -> str:
    if other.startswith('http'):
        return other
    return base + other

def url_to_data_path(base: str, url: str) -> str:
    urlparsed = urlparse(url)
    return path.join(base, urlparsed.hostname, urlparsed.path.lstrip('/')).replace('/', path.sep).replace('\\', path.sep)

def hex_str_to_iv(hex_str: str) -> bytes:
    if hex_str.startswith('0x'):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)