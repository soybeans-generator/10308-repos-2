import time
import hmac
import json
import hashlib
import base64
from urllib.parse import urlparse

def get_x_skyott_md5(headers:dict):
    final_headers = ""
    # get only x-skyott headers and create a string formatted like this header_name: value \newline
    for key in sorted(headers):
        if key.lower().startswith("x-skyott"):
            final_headers += f"{key}: {headers[key]}\n"
    # hash it in md5 and get the hex hash
    bytes_headers = final_headers.encode("utf-8")
    md5_headers = hashlib.md5(bytes_headers).hexdigest()
    return md5_headers

def get_payload_md5(payload):
    #Convert dict to json string
    if isinstance(payload, dict): payload_bytes = json.dumps(payload).encode()
    else: payload_bytes = payload.encode()
    payload_md5 = hashlib.md5(payload_bytes).hexdigest()
    return payload_md5



def get_signature(request_type:str, url:str, headers:dict, payload, timestamp:int=None):
    #Big shoutout to @xhlove for this https://gist.github.com/xhlove/b87d36370fcd825e4a2208df0fcb8085
    #THIS DOES NOT GENERATE THE WHOLE HEADER, THIS ONLY GENERATES THE SIGNATURE

    #define all variables
    if not timestamp:
        timestamp = int(time.time())
    signkey = bytearray('He97trFdwMSKZBbnJGjzyPXN3Qgu2qRvh4spkmcC', 'utf-8')
    # easier and lighter method to get path
    #path = url.replace("https://p.sky.com", "")
    path = urlparse(url).path
    headers_hash = get_x_skyott_md5(headers)
    payload_hash = get_payload_md5(payload)
    # this is the payload that sky checks
    http_request_str = f"{request_type}\n{path}\n\nNOWOTT-ANDROID-v1\n1.0\n{headers_hash}\n{timestamp}\n{payload_hash}\n"
    print(http_request_str)
    bytes_signature = hmac.new(signkey, http_request_str.encode("utf-8"), hashlib.sha1).digest()
    final_signature = base64.b64encode(bytes_signature).decode("utf-8")
    return final_signature, timestamp
