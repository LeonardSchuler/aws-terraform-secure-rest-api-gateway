import json
import webbrowser
import logging
import requests
import jwt
import click
from rich import print as rprint
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from requests_oauthlib import OAuth2Session
import threading

logging.getLogger().handlers.clear()
logger = logging.getLogger("requests_oauthlib.oauth2_session")
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def decode_token(token, user_pool_jwt_issuer_url, client_id):
    jwk_url = f"{user_pool_jwt_issuer_url}/.well-known/jwks.json"
    rprint(jwk_url)

    jwk_client = jwt.PyJWKClient(jwk_url)
    signing_key = jwk_client.get_signing_key_from_jwt(token)

    decoded_token = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=client_id,
        options={"verify_aud": False},
    )
    return decoded_token


def verify_token(decoded_token, client_id):
    aud = decoded_token.get("client_id") or decoded_token.get("aud")
    if aud != client_id:
        raise Exception("Invalid client_id or aud claim")


def rprint_token(token, user_pool_jwt_issuer_url, client_id):
    if token is None:
        return
    decoded_token = decode_token(token, user_pool_jwt_issuer_url, client_id)
    rprint(token)
    rprint(decoded_token)
    try:
        verify_token(decoded_token, client_id)
    except Exception as e:
        rprint(e.message)


class CallbackHandler(BaseHTTPRequestHandler):
    def __init__(
        self,
        *args,
        oauth,
        token_url,
        client_id,
        user_pool_jwt_issuer_url,
        api_url,
        auth_code_container,
        **kwargs,
    ):
        self.oauth = oauth
        self.token_url = token_url
        self.client_id = client_id
        self.user_pool_jwt_issuer_url = user_pool_jwt_issuer_url
        self.api_url = api_url
        self.auth_code_container = auth_code_container
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/callback":
            query = parse_qs(parsed_path.query)
            if "code" in query:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"""
                    <html>
                    <body>
                    <p>Authorization successful. You can close this window and return to your application.</p>
                    </body>
                    </html>
                """)
                authorization_code = query["code"][0]
                rprint(f"Authorization code received: {authorization_code}\n")
                self.auth_code_container["code"] = authorization_code
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Authorization code not found in the callback URL.")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")


@click.command()
@click.option("--scopes", prompt="OAuth Scopes", help="OAuth Scopes")
@click.option("--callback-url", prompt="Callback URL", help="Callback URL")
@click.option("--client-id", prompt="Client ID", help="Cognito User Pool Client ID")
@click.option("--token-url", prompt="Token URL", help="Token URL")
@click.option(
    "--user-pool-auth-domain",
    prompt="User Pool Auth Domain",
    help="User Pool Auth Domain",
)
@click.option(
    "--user-pool-jwt-issuer-url",
    prompt="User Pool JWT Issuer URL",
    help="User Pool JWT Issuer URL",
)
@click.option(
    "--api-url", prompt="API URL", help="API URL including path to hello route"
)
def main(
    scopes,
    callback_url,
    client_id,
    token_url,
    user_pool_auth_domain,
    user_pool_jwt_issuer_url,
    api_url,
):
    callback_parsed = urlparse(callback_url)
    REDIRECT_URL_PORT = callback_parsed.port
    REDIRECT_URL_HOST = callback_parsed.hostname

    oauth = OAuth2Session(
        client_id=client_id,
        scope=scopes.split(),
        redirect_uri=callback_url,
        pkce="S256",
    )

    auth_code_container = {}

    def run_server():
        with HTTPServer(
            (REDIRECT_URL_HOST, REDIRECT_URL_PORT),
            lambda *args, **kwargs: CallbackHandler(
                *args,
                oauth=oauth,
                token_url=token_url,
                client_id=client_id,
                user_pool_jwt_issuer_url=user_pool_jwt_issuer_url,
                api_url=api_url,
                auth_code_container=auth_code_container,
                **kwargs,
            ),
        ) as httpd:
            rprint(f"Serving at {callback_url}\n")
            httpd.handle_request()

    server_thread = threading.Thread(target=run_server)
    server_thread.start()

    authorization_url = f"{user_pool_auth_domain}/login"
    auth_url, _ = oauth.authorization_url(authorization_url)
    rprint(f"Opening login page to obtain an authorization token: {auth_url}\n")
    webbrowser.open(auth_url)

    server_thread.join()

    if "code" in auth_code_container:
        authorization_code = auth_code_container["code"]
        rprint(f"Authorization code received: {authorization_code}\n")

        rprint("Get id, access, and refresh tokens")
        token = oauth.fetch_token(
            token_url,
            code=authorization_code,
            client_id=client_id,
            include_client_id=True,
            client_secret=None,
        )
        rprint(token)
        access_token = token.get("access_token", None)
        id_token = token.get("id_token", None)
        refresh_token = token.get("refresh_token", None)

        rprint()
        rprint("Tokens")
        rprint(80 * "-")
        rprint("ID token")
        rprint_token(id_token, user_pool_jwt_issuer_url, client_id)
        rprint()
        rprint("Access token")
        rprint_token(access_token, user_pool_jwt_issuer_url, client_id)
        rprint()
        rprint("Refresh token")
        rprint(refresh_token)
        rprint()
        rprint(80 * "-")
        rprint("Performing the following authorized request against the API Gateway.")
        print(f'curl -H "Authorization: Bearer {token["access_token"]}" {api_url}\n')
        resp = requests.get(
            api_url,
            headers={"Authorization": f"Bearer {token['access_token']}"},
        )
        rprint(
            f"Request received '{resp.status_code}' response with body: '{resp.text}'"
        )
    else:
        rprint("Authorization code was not received.")


if __name__ == "__main__":
    main()
