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
from rest_framework.permissions import IsAuthenticated

from .models import *
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
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

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

    @swagger_auto_schema(request_body=WithdrawalReasonSerializer, responses={200: ''})
    def delete(self, request, *args, **kwargs):
        '''
        계정 탈퇴

        ---
        탈퇴 사유를 입력받아 저장한 후 계정을 삭제합니다.
        '''
        # 탈퇴 사유를 시리얼라이저로 검증
        serializer = WithdrawalReasonSerializer(data=request.data)
        if not serializer.is_valid():
            return custom_response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # 현재 인증된 사용자 정보에서 소셜 ID 추출
        social_id = request.user.social_id  # JWT 토큰을 통해 인증된 사용자 객체

        # 탈퇴 사유 저장
        UserWithdrawalReason.objects.create(social_id=social_id, reason=serializer.validated_data['reason'])

        # 사용자 계정 삭제
        request.user.delete()

        return custom_response(data={"status": True, "message": "회원 탈퇴가 완료되었습니다."}, status=status.HTTP_200_OK)


# Serializer for verifying token request
class TokenVerifySerializer(serializers.Serializer):
    token = serializers.CharField(write_only=True, required=True, help_text="JWT 토큰")


class TokenVerifyView(APIView):
    '''
    토큰 검증 API
    '''
    permission_classes = [AllowAny]
    authentication_classes = [JWTAuthentication]  # JWTAuthentication 사용

    @swagger_auto_schema(
        responses={
            200: openapi.Response(description="토큰 유효", examples={"application/json": {"status": True, "message": "유효한 토큰 입니다."}}),
            401: openapi.Response(description="토큰 무효", examples={"application/json": {"status": False, "message": "유효하지 않은 토큰입니다."}}),
            400: openapi.Response(description="헤더 오류", examples={"application/json": {"status": False, "message": "토큰이 필요합니다."}})
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

            # UntypedToken으로 직접 토큰의 유효성을 검증하고 request.user를 통해 유저 확인
            UntypedToken(token)

            if not request.user or not request.user.is_authenticated:
                raise InvalidToken("유효하지 않은 토큰입니다.")

            # 유저 정보가 있을 경우
            serializer = UserInfoSerializer(request.user)
            user_data = serializer.data

            return custom_response(
                data={"status": True, "message": "유효한 토큰입니다.", "user": user_data},
                status=status.HTTP_200_OK
            )

        except (InvalidToken, TokenError):
            # 커스텀 예외 메시지 반환
            return custom_response(
                data={"status": False, "message": "유효하지 않은 토큰입니다."},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception:
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
        
        
class BlockListView(APIView):
    """
    차단한 목록 보기
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        responses={
            200: openapi.Response(
                description="차단한 사용자 목록",
                examples={"application/json": [
                    {"id": 1, "question": 123, "user_id": "current_user", "blocked_user_id": "blocked_user1", "block_yn": "Y", "create_at": "2023-01-01T00:00:00Z", "update_at": "2023-01-01T00:00:00Z"},
                    {"id": 2, "question": 124, "user_id": "current_user", "blocked_user_id": "blocked_user2", "block_yn": "Y", "create_at": "2023-01-01T00:00:00Z", "update_at": "2023-01-01T00:00:00Z"}
                ]}
            )
        }
    )
    def get(self, request):
        user_id = request.user.social_id
        blocked_users = Block.objects.filter(user_id=user_id, block_yn='Y')
        serializer = BlockSerializer(blocked_users, many=True)

        return custom_response(data=serializer.data, status=status.HTTP_200_OK)
    
class BlockUserView(APIView):
    """
    유저 차단하기
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'question_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='차단할 게시글의 ID'),
                'blocked_user_id': openapi.Schema(type=openapi.TYPE_STRING, description='차단된 사용자의 ID')
            }
        ),
        responses={
            200: openapi.Response(description="유저 차단 성공", examples={"application/json": {"status": True, "message": "유저가 성공적으로 차단되었습니다."}}),
            400: openapi.Response(description="Bad Request", examples={"application/json": {"status": False, "message": "잘못된 요청입니다."}}),
        }
    )
    def post(self, request):
        user_id = request.user.social_id
        question_id = request.data.get('question_id')
        blocked_user_id = request.data.get('blocked_user_id')

        if not question_id or not blocked_user_id:
            return custom_response(data={"status": False, "message": "question_id와 blocked_user_id를 제공해야 합니다."}, status=status.HTTP_400_BAD_REQUEST)

        Block.objects.create(
            question=question_id,
            user_id=user_id,
            blocked_user_id=blocked_user_id
        )

        return custom_response(data={"status": True, "message": "유저가 성공적으로 차단되었습니다."}, status=status.HTTP_200_OK)
    
class UnblockUserView(APIView):
    """
    유저 차단 해제하기
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        responses={
            200: openapi.Response(description="유저 차단 해제 성공", examples={"application/json": {"status": True, "message": "유저 차단이 해제되었습니다."}}),
            400: openapi.Response(description="Bad Request", examples={"application/json": {"status": False, "message": "차단 기록이 존재하지 않습니다."}})
        }
    )
    def delete(self, request, blocked_user_id):
        user_id = request.user.social_id

        try:
            block_instance = Block.objects.get(user_id=user_id, blocked_user_id=blocked_user_id)
            block_instance.block_yn = 'N'
            block_instance.save(update_fields=['block_yn', 'update_at'])
            return custom_response(data={"status": True, "message": "유저 차단이 해제되었습니다."}, status=status.HTTP_200_OK)
        except Block.DoesNotExist:
            return custom_response(data={"status": False, "message": "차단 기록이 존재하지 않습니다."}, status=status.HTTP_400_BAD_REQUEST)
