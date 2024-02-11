from project.settings import (
    KAKAO_CLIENT_ID,
    KAKAO_CLIENT_SECRET,
    KAKAO_REDIRECT_URI,
)

class Kakao:
    CLIENT_ID = KAKAO_CLIENT_ID
    CLIENT_SECRET = KAKAO_CLIENT_SECRET
    RECIRECT_URI = KAKAO_REDIRECT_URI
    LOGIN_URL = "https://kauth.kakao.com/oauth/authorize"
    TOKEN_URL = "https://kauth.kakao.com/oauth/token"
    PROFILE_URL = "https://kapi.kakao.com/v2/user/me"

KAKAO = Kakao()

__all__ = [
    "KAKAO",
]