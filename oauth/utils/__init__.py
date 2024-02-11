from project.settings import (
    KAKAO_CLIENT_ID,
    KAKAO_CLIENT_SECRET,
    KAKAO_REDIRECT_URI,
    GOOGLE_CLIENT_ID,
    GOOGLE_SECRET,
    GOOGLE_REDIRECT_URI,
    APPLE_CLIENT_ID,
    APPLE_KEY_ID,
    APPLE_TEAM_ID,
    APPLE_PRIVATE_KEY,
    APPLE_REDIRECT_URI,
)

class Kakao:
    CLIENT_ID = KAKAO_CLIENT_ID
    CLIENT_SECRET = KAKAO_CLIENT_SECRET
    RECIRECT_URI = KAKAO_REDIRECT_URI
    LOGIN_URL = "https://kauth.kakao.com/oauth/authorize"
    TOKEN_URL = "https://kauth.kakao.com/oauth/token"
    PROFILE_URL = "https://kapi.kakao.com/v2/user/me"
    
    def __str__(self):
        return 'apple'

class Google:
    CLIENT_ID = GOOGLE_CLIENT_ID
    CLIENT_SECRET = GOOGLE_SECRET
    REDIRECT_URI = GOOGLE_REDIRECT_URI
    LOGIN_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    SCOPE = "https://www.googleapis.com/auth/userinfo.email"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    PROFILE_URL = "https://www.googleapis.com/oauth2/v2/tokeninfo"

    # Original
    # google_login_url = "https://accounts.google.com/o/oauth2/v2/auth"
    # google_scope = "https://www.googleapis.com/auth/userinfo.email"
    # google_token_url = "https://oauth2.googleapis.com/token"
    # google_profile_url = "https://www.googleapis.com/oauth2/v2/tokeninfo"
    
    def __str__(self):
        return 'google'

class Apple:
    CLIENT_ID = APPLE_CLIENT_ID
    KEY_ID = APPLE_KEY_ID
    TEAM_ID = APPLE_TEAM_ID
    PRIVATE_KEY = APPLE_PRIVATE_KEY
    REDIRECT_URI = APPLE_REDIRECT_URI
    BASE_URL = "https://appleid.apple.com"
    AUTH_URL = f"{BASE_URL}/auth/authorize"
    TOKEN_URL = f"{BASE_URL}/auth/token"

    def __str__(self):
        return 'apple'

KAKAO = Kakao()
GOOGLE = Google()
APPLE = Apple()


__all__ = [
    "KAKAO",
    "GOOGLE",
    "APPLE",
]