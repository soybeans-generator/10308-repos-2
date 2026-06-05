# Little note on the payload MD5: above I  "json dumps" a dict payload assuming
# zero spaces between keys and values (after : and {}), but this has to match
# what is used in the request... the slightest mismatch affect the MD5 and the
# signature! 

def md5_of_canonical_headers(headers):
    sky_headers = {
        k.lower(): v for k, v in headers.items()
        if k.lower().startswith("x-skyott")
    }
    canonical = ""
    for k in sorted(sky_headers):
        canonical += f"{k}: {sky_headers[k]}\n"
    md5_hash = hashlib.md5(canonical.encode("utf-8")).hexdigest()
    return md5_hash


def md5_payload(payload: str | bytes | dict) -> str:
    if isinstance(payload, dict):
        payload = json.dumps(payload, separators=(',', ':'))
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return hashlib.md5(payload).hexdigest()


def calculate_nowtvit_6_4_13(
        method: str,
        path: str,
        payload: any,
        headers: any,
        timestamp: int):
    signature_key = 'He97trFdwMSKZBbnJGjzyPXN3Qgu2qRvh4spkmcC'.encode()
    sig_version = '1.0'
    app_id = 'NOWOTT-ANDROID-v1'
    headers_md5 = md5_of_canonical_headers(headers)
    payload_md5 = md5_payload(payload)
    to_hash = '{method}\n{path}\n{response_code}\n{app_id}\n{version}\n{headers_md5}\n{timestamp}\n{payload_md5}\n'.format(method=method, path=path,
                                                      response_code='', app_id=app_id, version=sig_version,
                                                      headers_md5=headers_md5, timestamp=timestamp,
                                                      payload_md5=payload_md5)
    # a_input = base64.b64encode(to_hash.encode())
    # print(f'INPUT: {a_input}')
    hashed = hmac.new(signature_key, to_hash.encode(), hashlib.sha1).digest()
    signature = base64.b64encode(hashed).decode()
    signature_final = 'SkyOTT client="{}",signature="{}",timestamp="{}",version="{}"'.format(app_id, signature, timestamp,
                                                                                  sig_version)
    return signature_final
