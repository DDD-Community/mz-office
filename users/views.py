from rest_framework import status
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework import status

from .serializers import *
from .permission import LoginRequired

from project.utils import custom_response 

# Define the response schema for 200 responses
nickname_check_response_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'exists': openapi.Schema(type=openapi.TYPE_BOOLEAN, description='닉네임 응답 여부 (True: 사용 가능, False: 사용 불가)'),
        'message': openapi.Schema(type=openapi.TYPE_STRING, description='닉네임 유효성 검사 (공백 불가)')
    }
)

# Define the response object for 200 responses
nickname_check_response = openapi.Response(
    description="Nickname check response",
    schema=nickname_check_response_schema,
    examples={
        "application/json": {"exists": False, "message": "사용 불가능한 닉네임 입니다."},
        "application/json": {"exists": True, "message": "사용 가능한 닉네임 입니다."},
        "application/json": {"exists": False, "message": "닉네임에 공백이 들어갈 수 없습니다."}
    }
)

user_retrieve_response = openapi.Response('', UserInfoSerializer)

class UserView(APIView):
    permission_classes = [AllowAny]

    def get_or_create_user(self, data: dict):
        serializer = CreateUserSerializer(data=data)

        if not serializer.is_valid():
            return custom_response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data
        serializer.create(validated_data=user)

        return custom_response(data=user, status=status.HTTP_201_CREATED)

    def post(self, request):
        '''
        계정 조회 및 등록

        ---
        '''
        return self.get_or_create_user(data=request.data)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def object(self, data: dict):
        serializer = LoginSerializer(data=data)
        if not serializer.is_valid():
            return custom_response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data

        return custom_response(data=user, status=status.HTTP_200_OK)

    def post(self, request):
        '''
        로그인

        ---
        '''
        return self.object(data=request.data)


class LogoutView(APIView):
    permission_classes = [LoginRequired]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(request_body=LogoutSerializer)
    def post(self, request):
        '''
        로그아웃

        ---
        '''
        serializer = LogoutSerializer(data=request.data)
        if not serializer.is_valid():
            return custom_response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # 사용자를 블랙리스트 처리하거나 토큰 무효화
        serializer.validated_data.blacklist()

        # 사용자 정보 가져오기
        user = request.user

        # 사용자 정보를 직렬화
        user_serializer = UserInfoSerializer(user)

        # 사용자 정보와 함께 응답 반환
        return custom_response(data=user_serializer.data, status=status.HTTP_200_OK)


class TokenRefreshView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(request_body=RefreshTokenSerializer)
    def post(self, request):
        '''
        Access Token 재발급

        ---
        '''
        serializer = RefreshTokenSerializer(data=request.data)

        if not serializer.is_valid():
            return custom_response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        token = serializer.validated_data

        return custom_response(data=token, status=status.HTTP_201_CREATED)


class MerberView(APIView):
    '''
    계정 정보
    '''
    @swagger_auto_schema(responses={200: user_retrieve_response})
    def get(self, request):
        '''
        로그인한 계정 정보 조회

        ---
        사용자 계정 ID, 이메일, 가입일자, 최근 로그인 일자 조회
        '''
        serializer = UserInfoSerializer(request.user)
        response_data = serializer.data

        return custom_response(data=response_data, status=status.HTTP_200_OK)

    @swagger_auto_schema(request_body=UserInfoPhoneSerializer, responses={200: ''})
    def patch(self, request, *args, **kwargs):
        '''
        계정 정보 수정

        ---
        '''
        data = request.data

        serializer = UserInfoPhoneSerializer(request.user, data=data, partial=True)
        if not serializer.is_valid():
            return custom_response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        serializer.save()
        
        # 수정된 유저 정보를 직렬화하여 반환
        response_data = UserInfoSerializer(request.user).data

        return custom_response(data=response_data, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        '''
        계정 삭제

        ---
        '''
        request.user.delete()

        return custom_response(status=status.HTTP_204_NO_CONTENT)

# Serializer for verifying token request
class TokenVerifySerializer(serializers.Serializer):
    token = serializers.CharField(write_only=True, required=True, help_text="JWT 토큰")


class TokenVerifyView(APIView):
    '''
    토큰 검증 API
    '''
    permission_classes = [AllowAny]
    authentication_classes = []  # JWTAuthentication 대신 직접 토큰을 검증합니다.

    @swagger_auto_schema(
        responses={
            200: openapi.Response(description="토큰 유효", examples={"application/json": {"valid": True}}),
            401: openapi.Response(description="토큰 무효", examples={"application/json": {"valid": False, "error": "유효하지 않은 토큰입니다."}}),
            400: openapi.Response(description="헤더 오류", examples={"application/json": {"error": "토큰이 필요합니다."}})
        }
    )
    def post(self, request):
        '''
        토큰의 유효성을 검증

        ---
        '''
        auth_header = request.headers.get('Authorization')

        if auth_header is None:
            return custom_response(
                data={"status": False, "message": "토큰이 필요합니다."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Authorization 헤더가 올바른 형식인지 확인
        if not auth_header.startswith('Bearer '):
            return custom_response(
                data={"status": False, "message": "올바른 인증 헤더 형식이 아닙니다."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Bearer {token}에서 토큰 부분만 추출
            token = auth_header.split(' ')[1]

            # 토큰의 유효성을 직접 검증
            UntypedToken(token)
            return custom_response(data={"status": True, "message": "유효한 토큰 입니다."}, status=status.HTTP_200_OK)

        except (InvalidToken, TokenError) as e:
            # 커스텀 예외 메시지 반환
            return custom_response(
                data={"status": False, "message": "유효하지 않은 토큰입니다."},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as e:
            # 기타 모든 예외 처리
            return custom_response(
                data={"status": False, "message": "유효하지 않은 토큰입니다."},
                status=status.HTTP_401_UNAUTHORIZED
            )


class JobSerializer(serializers.Serializer):
    data = serializers.ListField(
        child=serializers.CharField()
    )

class JobListAPIView(GenericAPIView):
    """Job 목록"""
    permission_classes = [AllowAny]
    serializer_class = JobSerializer  # serializer_class 추가

    def get(self, request, *args, **kwargs):
        jobs = ["경영", "광고", "기획", "개발", "데이터", "디자인", "마케팅", "방송", "운영", "이커머스", "게임", "금융", "회계", "인사", "영업", "물류", "연구", "의료", "제약", "엔지니어링", "생산품질", "교육", "법률", "공공", "서비스", "기타"]
        serializer = self.get_serializer(data={'data': jobs})
        serializer.is_valid()
        return custom_response(data=serializer.data)


class NicknameCheckAPIView(APIView):
    """Nickname 유효성 체크"""
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        manual_parameters=[openapi.Parameter('nickname', openapi.IN_QUERY, description="닉네임", type=openapi.TYPE_STRING)],
        responses={
            200: nickname_check_response,
            400: openapi.Response(description="Bad Request", examples={"application/json": {"error": "닉네임을 입력해주세요."}}),
        }
    )
    def get(self, request, *args, **kwargs):
        nickname = request.query_params.get('nickname')

        if not nickname:
            return custom_response(data={"error": "닉네임을 입력해주세요."}, status=status.HTTP_400_BAD_REQUEST)

        if ' ' in nickname or nickname.strip() != nickname:
            return custom_response(data={"exists": False, "message": "닉네임에 공백이 들어갈 수 없습니다."}, status=status.HTTP_200_OK)

        if UserModel.objects.filter(nickname=nickname).exists():
            return custom_response(data={"exists": False, "message": "사용 불가능한 닉네임 입니다."}, status=status.HTTP_200_OK)
        else:
            return custom_response(data={"exists": True, "message": "사용 가능한 닉네임 입니다."}, status=status.HTTP_200_OK)