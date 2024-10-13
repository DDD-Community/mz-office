# notifications/views.py

from rest_framework.permissions import AllowAny
from rest_framework.mixins import CreateModelMixin
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import Notification
from .serializers import NotificationSerializer

notification_post_body = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'position': openapi.Schema(type=openapi.TYPE_STRING, description='지원 포지션 (예: 백엔드, 프론트엔드, iOS, 안드로이드 등)'),
        'support_path': openapi.Schema(type=openapi.TYPE_STRING, description='지원 경로 (예: 인스타그램, 카카오톡, 지인추천 등)'),
        'name': openapi.Schema(type=openapi.TYPE_STRING, description='지원자 이름'),
        'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL, description='지원자 이메일 주소'),
    },
    required=['position', 'support_path', 'name', 'email']
)

class NotificationAPIView(CreateModelMixin, GenericAPIView):
    permission_classes = [AllowAny]

    """모집 알림 신청 등록"""
    queryset = Notification.objects.all()
    serializer_class = NotificationSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    @swagger_auto_schema(
        request_body=notification_post_body,
        responses={201: NotificationSerializer, 400: 'Bad Request'},
        operation_description="모집 알림 신청을 등록하는 API입니다.",
        operation_summary="모집 알림 신청 등록 API"
    )
    def post(self, request, *args, **kwargs):
        response = self.create(request, *args, **kwargs)
        return Response(
            data=response.data,
            status=status.HTTP_201_CREATED
        )