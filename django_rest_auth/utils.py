from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from .exception.InvalidGoogleAuthCodeException import InvalidGoogleAuthCodeException
from .exception.InvalidGoogleIDTokenException import InvalidGoogleIDTokenException
from .settings import CLIENT_ID, CLIENT_SECRET
import requests

GOOGLE_AUTH_TOKEN_URL = 'https://oauth2.googleapis.com/token?'
GRANT_TYPE = 'authorization_code'
REDIRECT_URI = 'http://localhost:9090/login-callback'


def google_get_id_token_from_auth_code(auth_code: str) -> str:
    """
    This function yields the authorization code associated identity token.
    This id_token will be used for retrieving the personal identity associated with
    the email account
    """
    session = requests.Session()
    param_argument = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': auth_code,
        'grant_type': GRANT_TYPE,
        'redirect_uri': REDIRECT_URI
    }

    # Generating parameterized URL
    parameterized_url = GOOGLE_AUTH_TOKEN_URL
    for param, argument in param_argument.items():
        searchParam = param + '=' + argument
        parameterized_url += searchParam + '&'

    response = session.post(parameterized_url)
    response_data = response.json()
    try:
        return response_data['id_token']

    except:
        raise InvalidGoogleAuthCodeException


def google_get_profile_from_id_token(identity_token: str) -> dict:
    identity_info: dict = id_token.verify_oauth2_token(identity_token, google_requests.Request(), CLIENT_ID)
    if not identity_info.get('sub'):
        raise InvalidGoogleIDTokenException

    return identity_info


def get_or_create_user(user_data):
    user_email = user_data.get('email')
    found_user = User.objects.filter(email=user_email)

    if len(found_user) > 0:
        return found_user[0]
    else:
        first_name = user_data.get('given_name')
        last_name = user_data.get('family_name')
        user = User(email=user_email, first_name=first_name, last_name=last_name)
        user.save()
        return user


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
