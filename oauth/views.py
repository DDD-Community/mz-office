import requests, jwt, time, os, json

from django.conf import settings
from django.shortcuts import redirect
from django.middleware.csrf import get_token
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from users.models import UserModel
from pathlib import Path
from oauth.utils import (
    KAKAO,
    GOOGLE,
    APPLE,
)

from .serializers import *
from users.models import UserModel
from users.views import LoginView, UserView
from django.core.exceptions import ImproperlyConfigured
import logging
from datetime import datetime, timedelta

logger = logging.getLogger('django.request')

def login_api(social_type: str, social_id: str, email: str=None, phone: str=None):
    '''
    회원가입 및 로그인
    '''
    logger.debug("1. login_api 호출됨 - social_type: %s, social_id: %s, email: %s", social_type, social_id, email)
    login_view = LoginView()
    try:
        UserModel.objects.get(social_id=social_id)
        data = {
            'social_id': social_id,
            'email': email,
        }
        logger.debug("2. UserModel 조회 성공 - social_id: %s", social_id)
        response = login_view.object(data=data)
    except UserModel.DoesNotExist:
        logger.debug("3. UserModel 조회 실패 - 신규 사용자, social_id: %s", social_id)
        data = {
            'social_type': social_type,
            'social_id': social_id,
            'email': email,
        }
        user_view = UserView()
        login = user_view.get_or_create_user(data=data)
        logger.debug("4. 신규 사용자 생성 결과 - status_code: %s", login.status_code)
        response = login_view.object(data=data) if login.status_code == 201 else login

    logger.debug("5. login_api 응답 - status_code: %s", response.status_code)
    return response


class KakaoLoginView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        '''
        kakao code 요청

        ---
        '''
        client_id = KAKAO.CLIENT_ID
        redirect_uri = KAKAO.RECIRECT_URI
        uri = f"{KAKAO.LOGIN_URL}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code"

        logger.debug("6. KakaoLoginView GET 호출 - 리다이렉트 URI: %s", uri)
        res = redirect(uri)
        return res


class KakaoCallbackView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(query_serializer=CallbackUserInfoSerializer)
    def get(self, request):
        logger.debug("7. KakaoCallbackView GET 호출 - request query params: %s", request.query_params)
        data = request.query_params

        # iOS에서 전달된 access_token 확인
        access_token = data.get('access_token')
        code = data.get('code')
        logger.debug("8. KakaoCallbackView GET - code: %s, access_token: %s", code, access_token)

        expires_in = None
        refresh_token_expires_in = None

        if not access_token and code:
            # access_token 발급 요청
            request_data = {
                'grant_type': 'authorization_code',
                'client_id': KAKAO.CLIENT_ID,
                'redirect_uri': KAKAO.RECIRECT_URI,
                'client_secret': KAKAO.CLIENT_SECRET,
                'code': code,
            }
            token_headers = {
                'Content-type': 'application/x-www-form-urlencoded;charset=utf-8'
            }
            logger.debug("10. Kakao access_token 요청 - request_data: %s", request_data)
            token_res = requests.post(KAKAO.TOKEN_URL, data=request_data, headers=token_headers)
            logger.debug("11. Kakao access_token 응답 - status_code: %s, response: %s", token_res.status_code, token_res.text)

            token_json = token_res.json()
            access_token = token_json.get('access_token')
            expires_in = token_json.get('expires_in')
            refresh_token_expires_in = token_json.get('refresh_token_expires_in')

            if not access_token:
                logger.debug("12. Kakao access_token 응답 실패 - access_token 없음")
                return Response(status=status.HTTP_400_BAD_REQUEST)

            # expires_in 또는 refresh_token_expires_in이 None인 경우 처리
            if expires_in is None or refresh_token_expires_in is None:
                logger.error("Kakao API response missing 'expires_in' or 'refresh_token_expires_in': %s", token_json)
                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR, data={'error': 'Invalid token response'})

            access_token = f"Bearer {access_token}"  # 'Bearer ' 마지막 띄어쓰기 필수

        elif not access_token:
            logger.debug("9. KakaoCallbackView GET - code와 access_token 없음")
            return Response(status=status.HTTP_400_BAD_REQUEST)
        else:
            access_token = f"Bearer {access_token}"  # iOS에서 전달된 access_token 사용

        # kakao 회원정보 요청
        auth_headers = {
            "Authorization": access_token,
            "Content-type": "application/x-www-form-urlencoded;charset=utf-8",
        }
        logger.debug("13. Kakao 회원정보 요청 - access_token: %s", access_token)
        user_info_res = requests.get(KAKAO.PROFILE_URL, headers=auth_headers)
        logger.debug("14. Kakao 회원정보 응답 - status_code: %s, response: %s", user_info_res.status_code, user_info_res.text)

        user_info_json = user_info_res.json()

        social_type = 'kakao'
        social_id = f"{social_type}_{user_info_json.get('id')}"

        kakao_account = user_info_json.get('kakao_account')
        if not kakao_account:
            logger.debug("15. Kakao 회원정보 응답 실패 - kakao_account 없음")
            return Response(status=status.HTTP_400_BAD_REQUEST)
        user_email = kakao_account.get('email')

        # 회원가입 및 로그인
        logger.debug("16. login_api 호출 전 - social_type: %s, social_id: %s, email: %s", social_type, social_id, user_email)
        res = login_api(social_type=social_type, social_id=social_id, email=user_email)
        logger.debug("17. login_api 응답 - status_code: %s", res.status_code)

        # 만약 `res`가 Response 객체라면, 데이터에 토큰 정보를 추가합니다.
        if isinstance(res, Response):
            current_time = datetime.utcnow()
            access_token_expiry_time = current_time + timedelta(seconds=expires_in)
            refresh_token_expiry_time = current_time + timedelta(seconds=refresh_token_expires_in)

            is_expires = current_time >= access_token_expiry_time
            is_refresh_token_expires = current_time >= refresh_token_expiry_time

            res.data['data']['expires_in'] = expires_in
            res.data['data']['refresh_token_expires_in'] = refresh_token_expires_in
            res.data['data']['is_expires'] = is_expires
            res.data['data']['is_refresh_token_expires'] = is_refresh_token_expires

        return res


class GoogleLoginView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        '''
        google code 요청

        ---
        '''
        client_id = GOOGLE.CLIENT_ID
        redirect_uri = GOOGLE.REDIRECT_URI
        uri = f"{GOOGLE.LOGIN_URI}?client_id={client_id}&redirect_uri={redirect_uri}&scope={GOOGLE.SCOPE}&response_type=code"

        res = redirect(uri)
        return res


class GoogleCallbackView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(query_serializer=CallbackUserInfoSerializer)
    def get(self, request):
        '''
        google access_token 및 user_info 요청

        ---
        '''
        data = request.query_params

        # access_token 발급 요청
        code = data.get('code')
        if not code:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        request_data = {
            'client_id': GOOGLE.CLIENT_ID,
            'client_secret': GOOGLE.CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': GOOGLE.REDIRECT_URI,
        }
        token_res = requests.post(GOOGLE.TOKEN_URI, data=request_data)

        token_json = token_res.json()
        access_token = token_json['access_token']

        if not access_token:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        # google 회원정보 요청
        query_string = {
            'access_token': access_token
        }
        user_info_res = requests.get(GOOGLE.PROFILE_URI, params=query_string)
        user_info_json = user_info_res.json()
        if (user_info_res.status_code != 200) or (not user_info_json):
            return Response(status=status.HTTP_400_BAD_REQUEST)

        social_type = 'google'
        social_id = f"{social_type}_{user_info_json.get('user_id')}"
        user_email = user_info_json.get('email')

        # 회원가입 및 로그인
        res = login_api(social_type=social_type, social_id=social_id, email=user_email)
        return res


class AppleLoginView(APIView):
    permission_classes = [AllowAny]

    def get(self, reqeust):
        '''
        apple code 요청

        ---
        '''
        # APPLE_CLIENT_ID는 모바일 로그인시 Bundle ID, 웹 로그인시 Service ID를 사용한다.
        client_id = APPLE.CLIENT_ID
        redirect_uri = APPLE.REDIRECT_URI

        uri = f"{APPLE.AUTH_URL}?client_id={client_id}&&redirect_uri={redirect_uri}&response_type=code"

        res = redirect(uri)
        return res


class AppleCallbackView(APIView):
    permission_classes = [AllowAny]

    def get_key_and_secret(self):
        '''
        CLIENT_SECRET 생성
        '''
        headers = {
            'alg': 'ES256',
            'kid': APPLE.KEY_ID,
        }

        payload = {
            'iss': APPLE.TEAM_ID,
            'iat': time.time(),
            'exp': time.time() + 600,  # 10분
            'aud': APPLE.BASE_URL,
            'sub': APPLE.CLIENT_ID,
        }

        client_secret = jwt.encode(
            payload=payload,
            key=APPLE.PRIVATE_KEY,
            algorithm='ES256',
            headers=headers
        )

        return client_secret

    @swagger_auto_schema(query_serializer=CallbackAppleInfoSerializer)
    def get(self, request):
        '''
        apple id_token 및 user_info 조회

        ---
        '''
        data = request.query_params
        code = data.get('code')
        # id_token 서명 복호화시 에러로 검증할 수 없어 자체 발급한 id_token만 사용

        # CLIENT_SECRET 생성
        client_secret = self.get_key_and_secret()

        headers = {'Content-type': "application/x-www-form-urlencoded"}
        request_data = {
            'client_id': APPLE.CLIENT_ID,
            'client_secret': client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': APPLE.REDIRECT_URI,
        }
        # client_secret 유효성 검사
        res = requests.post(APPLE.TOKEN_URL, data=request_data, headers=headers)
        response_json = res.json()
        id_token = response_json.get('id_token')
        if not id_token:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        # 백엔드 자체적으로 id_token 발급받은 경우 서명을 검증할 필요 없음
        token_decode = jwt.decode(id_token, '', options={"verify_signature": False})
        # sub : (subject) is the unique user id
        # email : is the email address of the user

        if (not token_decode.get('sub')) or (not token_decode.get('email')) or (not token_decode.get('email_verified')):
            return Response(status=status.HTTP_400_BAD_REQUEST)

        # Apple에서 받은 id_token에서 sub, email 조회
        social_type = 'apple'
        social_id = f"{social_type}_{token_decode['sub']}"
        user_email = token_decode['email']

        # 회원가입 및 로그인
        res = login_api(social_type=social_type, social_id=social_id, email=user_email)
        return res


class AppleEndpoint(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        '''
        apple 사용자 정보수정

        ---
        이메일 변경, 서비스 해지, 계정 탈퇴에 대한 정보를 받는용
        '''
        data = request.data

        response = Response(status=status.HTTP_200_OK)
        return response