from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.shortcuts import redirect
from .utils import (
    google_get_id_token_from_auth_code,
    google_get_profile_from_id_token,
    get_or_create_user,
    get_tokens_for_user
)

CLIENT_CALLBACK_API = 'http://localhost:5500'


@api_view(['GET'])
def login_callback(request):
    auth_token = request.GET.get('code')
    id_token = google_get_id_token_from_auth_code(auth_token)
    user_profile = google_get_profile_from_id_token(id_token)
    user = get_or_create_user(user_profile)
    tokens = get_tokens_for_user(user)

    response = redirect(CLIENT_CALLBACK_API)
    response.set_cookie('tokens', tokens)

    return response
