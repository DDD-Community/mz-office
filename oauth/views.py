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
    
    login_view = LoginView()
    try:
        UserModel.objects.get(social_id=social_id)
        data = {
            'social_id': social_id,
            'email': email,
        }
        
        response = login_view.object(data=data)
    except UserModel.DoesNotExist:
        
        data = {
            'social_type': social_type,
            'social_id': social_id,
            'email': email,
        }
        user_view = UserView()
        login = user_view.get_or_create_user(data=data)
        
        response = login_view.object(data=data) if login.status_code == 201 else login

    
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

        
        res = redirect(uri)
        return res


class KakaoCallbackView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(query_serializer=CallbackUserInfoSerializer)
    def get(self, request):
        
        data = request.query_params

        # iOS에서 전달된 access_token 확인
        access_token = data.get('access_token')
        code = data.get('code')
        

        expires_in = 0
        refresh_token_expires_in = 0

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
            
            token_res = requests.post(KAKAO.TOKEN_URL, data=request_data, headers=token_headers)
            

            token_json = token_res.json()
            access_token = token_json.get('access_token')
            expires_in = token_json.get('expires_in')
            refresh_token_expires_in = token_json.get('refresh_token_expires_in')

            if not access_token:
                
                return Response(status=status.HTTP_400_BAD_REQUEST)

            access_token = f"Bearer {access_token}"  # 'Bearer ' 마지막 띄어쓰기 필수

        elif not access_token:
            
            return Response(status=status.HTTP_400_BAD_REQUEST)
        else:
            access_token = f"Bearer {access_token}"  # iOS에서 전달된 access_token 사용

        # kakao 회원정보 요청
        auth_headers = {
            "Authorization": access_token,
            "Content-type": "application/x-www-form-urlencoded;charset=utf-8",
        }
        
        user_info_res = requests.get(KAKAO.PROFILE_URL, headers=auth_headers)
        

        user_info_json = user_info_res.json()

        social_type = 'kakao'
        social_id = f"{social_type}_{user_info_json.get('id')}"

        kakao_account = user_info_json.get('kakao_account')
        if not kakao_account:
            
            return Response(status=status.HTTP_400_BAD_REQUEST)
        user_email = kakao_account.get('email')

        # 회원가입 및 로그인
        
        res = login_api(social_type=social_type, social_id=social_id, email=user_email)
        

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

    def get(self, request):
        '''
        apple code 요청

        ---
        '''
        client_id = APPLE.CLIENT_ID
        redirect_uri = APPLE.REDIRECT_URI
        uri = f"{APPLE.AUTH_URL}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code"

        
        res = redirect(uri)
        return res


class AppleCallbackView(APIView):
    permission_classes = [AllowAny]

    def get_key_and_secret(self):
        '''
        CLIENT_SECRET 생성
        '''
        logger.info("Apple Client Secret 생성 시작")
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
        
        logger.info("Apple Client Secret 생성 완료")
        return client_secret

    @swagger_auto_schema(query_serializer=CallbackAppleInfoSerializer)
    def get(self, request):
        '''
        Apple id_token 및 user_info 조회

        ---
        '''
        logger.info("Apple 로그인 콜백 요청 시작")
        data = request.query_params
        access_token = data.get('access_token')
        code = data.get('code')

        # code와 access_token이 모두 없으면 에러 반환
        if not code and not access_token:
            logger.error("code와 access_token이 없음")
            return Response(status=status.HTTP_400_BAD_REQUEST)

        if code:
            # code가 있을 때: Apple 서버에서 access_token 발급 요청
            logger.info(f"Authorization code 확인: {code}")
            client_secret = self.get_key_and_secret()

            request_data = {
                'grant_type': 'authorization_code',
                'client_id': APPLE.CLIENT_ID,
                'client_secret': client_secret,
                'code': code,
                'redirect_uri': APPLE.REDIRECT_URI,
            }
            token_headers = {
                'Content-type': 'application/x-www-form-urlencoded;charset=utf-8'
            }

            logger.info("Apple 서버에 토큰 요청 시작")
            token_res = requests.post(APPLE.TOKEN_URL, data=request_data, headers=token_headers)
            token_json = token_res.json()

            logger.info(f"Apple 서버 응답 수신: {token_json}")
            access_token = token_json.get('access_token')
            id_token = token_json.get('id_token')
            expires_in = token_json.get('expires_in', 0)
            refresh_token_expires_in = token_json.get('refresh_token_expires_in', 0)

            if not id_token:
                logger.error("Apple에서 id_token 발급 실패")
                return Response(status=status.HTTP_400_BAD_REQUEST)

        else:
            # access_token이 있을 때: 클라이언트에서 전달된 access_token 사용
            logger.info(f"클라이언트에서 전달된 access_token 확인: {access_token}")
            id_token = access_token  # access_token이 곧 id_token 역할을 함
            expires_in = 0  # 만료 시간 정보가 없을 수 있으므로 0으로 설정
            refresh_token_expires_in = 0

        # id_token 디코딩 및 사용자 정보 추출
        logger.info("Apple id_token 디코딩 시작")
        token_decode = jwt.decode(id_token, '', options={"verify_signature": False})
        logger.info(f"디코딩된 id_token 정보: {token_decode}")

        if not token_decode.get('sub') or not token_decode.get('email') or not token_decode.get('email_verified'):
            logger.error("Apple 사용자 정보 부족: sub, email, email_verified 필수 항목 누락")
            return Response(status=status.HTTP_400_BAD_REQUEST)

        social_type = 'apple'
        social_id = f"{social_type}_{token_decode['sub']}"
        user_email = token_decode['email']

        # 회원가입 및 로그인 처리
        logger.info(f"회원가입 또는 로그인 처리 시작: social_id={social_id}, email={user_email}")
        res = login_api(social_type=social_type, social_id=social_id, email=user_email)

        # 토큰 정보 추가
        if isinstance(res, Response):
            current_time = datetime.utcnow()
            access_token_expiry_time = current_time + timedelta(seconds=expires_in)
            refresh_token_expiry_time = current_time + timedelta(seconds=refresh_token_expires_in)

            is_expires = current_time >= access_token_expiry_time
            is_refresh_token_expires = current_time >= refresh_token_expiry_time

            logger.info(f"토큰 만료 정보 추가: access_token 만료 여부={is_expires}, refresh_token 만료 여부={is_refresh_token_expires}")

            res.data['data']['expires_in'] = expires_in
            res.data['data']['refresh_token_expires_in'] = refresh_token_expires_in
            res.data['data']['is_expires'] = is_expires
            res.data['data']['is_refresh_token_expires'] = is_refresh_token_expires

        logger.info("Apple 로그인 콜백 처리 완료")
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