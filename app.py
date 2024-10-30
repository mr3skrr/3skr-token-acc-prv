from flask import Flask, jsonify, request
import base64
import requests
from byte import *
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

def convert_to_hex(PAYLOAD):
    hex_payload = ''.join([f'{byte:02x}' for byte in PAYLOAD])
    return hex_payload

def convert_to_bytes(PAYLOAD):
    payload = bytes.fromhex(PAYLOAD)
    return payload

def get_token(password, UID):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br", "Connection": "close"
    }
    data = {
        "uid": UID,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    response = requests.post(url, headers=headers, data=data)
    data = response.json()
    ACCESS_TOKEN = data["access_token"]
    OPEN_ID = data["open_id"]
    return TOKEN_MAKE(ACCESS_TOKEN, OPEN_ID, UID)

def TOKEN_MAKE(ACCESS_TOKEN, OPEN_ID, UID):
    PAYLOAD = bytes.fromhex("43b9ed02ee3be05736e1d6269d345133b3b492a6aecf16fef49ee352996825ee7e495f8599c866f8b72fa72f6be26bb392fdf6e3961e5baa65116412dad8fb2b8258f06757ae3e0cddda40a4a05d6257ebd2733eb11130e46f73919820e29cedd5fa76498aad521be0673066d39858631f55d1211221271485af8c1d9a99dc5384be82fd3a2e6dc90d653672b081a8f3efb63f2c1abe31cef6eb757b48e3dc5120accd080184714a6b8f9d6ee937d82697dc5f743379d2cc79d17a83aef86f84b2f4285a48fa27d62fad0b9099e5ab00ecd77245908b1fdd41e34a32e0e9d8104980da4a5ebc8bf151296399c53e2c628977f644bcdc67edee6b492d1e7458f8423c5f1a1f6f02817de6e795ab5e09dac41893169354892d8fb98a6c01a909d1b0731d5e0231632091cc6391ecf5f367db11154a67596d37a117c655d4deb67683f6b54b672171df396ce46048cfbcba936a3625686c9d0ebfb0d70f66f0cf0650358fe1b2fcad4af5495993d8d3ee01b5a1bd032d6ea22549071549e119ec1456468699add3cce307cb29a3aff04a1357030d49edfd211b1887e1abb1deac6a875ca376b95da6d80a3a335b75d0f479d9fa0a609c196623f8c4ba12b4e5033b1cc3d651d3c725097f932f8268ba4ffdb9b19357f85c2da14c119ad7cfb825032b8af17680d686200b1a74f6df38f057b30c478fb6cdf5b55c2f282dae49a439346321ce266760f1461856872dc48e6650aa91efe2f322b64100e76aa57e4469698fe493f0594dab070564ba01a67affc972d2f23c522c5720f097e6b974f56cf787c8b816cc79f7e91b1d3aadb225ecc2e84e12e5da08a9d2076a7cc9adefed0dcf4332b6457794cb5da7947156728c3da08df81aa64dd63179ce254c95434b3703ae6fa7753482b75283d0283c0e0ff7ebdb8eb86f29759ad75c2f072ac960d09d746cf7ef59f8b7bea771f5f662114bf196d4b6a3a1ca9cefbba47571b5aff47d073a54bdb3acd97942b88002a7cb3ae311075b1237e1e21eab211feeec8b86c7829e6a6ab08d6c0a1c5463202776df0a179a955eaa235aad12b4d3eda67108ab0ef31206a270f01d6f018cad8702b0498dd64c28b3127ebcb275245eb1bf986dd9d202b2b3ab1ac220815829611984ccb397464d0c534fce2fbf2bc12256c1c17ad8b60895d385d52cba10c2b97d6dc22ce1234d57e9936c639002f31831de83cbc05df8a8e8c4afe4eb49d3eaad9910c365588d61abd90fe498a2a7683c75cdbf1c1522d251fd55898bef6487ec")
    encrypted_data = encrypt_api(bytes.fromhex(decrypt_api(convert_to_hex(PAYLOAD))).replace("c5a8e6bfd6ff9246a9cc4e043f7f5753".encode(), OPEN_ID.encode()).replace("37c00ba521e42f7fb8e374a2b5d07c2417e054abca6d7e0f25a83a8243f1d00a".encode(), ACCESS_TOKEN.encode()).hex())
    payload = convert_to_bytes(encrypted_data)
    URL = "https://loginbp.common.ggbluefox.com/MajorLogin"
    headers = {
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB46",
        "Authorization": "Bearer ",
        "Host": "loginbp.common.ggbluefox.com"
    }
    response = requests.post(URL, headers=headers, data=payload, verify=False)
    if response.status_code == 200:
        if len(response.text) < 10:
            return True
        BASE64_TOKEN = response.text[response.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):]
        second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
        BASE64_TOKEN = BASE64_TOKEN[:second_dot_index + 44]
        return BASE64_TOKEN
    return None

@app.route('/<password>/<token>', methods=['POST'])
def api_get_token(password, token):
    data = request.json
    UID = data.get("UID")
    if not UID:
        return jsonify({"error": "Missing UID"}), 400
    token_result = get_token(password, UID)
    if token_result:
        return jsonify([{"token": token_result}])
    return jsonify({"error": "Failed to generate token"}), 500

if __name__ == '__main__':
    app.run(debug=True)
