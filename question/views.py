from django.shortcuts import render
from django.core.serializers import serialize

from rest_framework.pagination import PageNumberPagination
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.mixins import (
    ListModelMixin,
    RetrieveModelMixin,
    CreateModelMixin,
    UpdateModelMixin,
    DestroyModelMixin,
)

from users.permission import IsAdminOrReadOnly
from .serializers import (
    QuestionSerializer,
    QuestionCreateSerializer,
    AnswerSerializer,
    ReportSerializer,
    LikeSerializer,
    BlockSerializer,
)
from .models import (
    Question,
    Answer,
    Report,
    Like,
    Block,
)


class CustomPageNumberPagination(PageNumberPagination):
    page_size_query_param = 'page_size'  # 페이지당 보여질 아이템 수를 파라미터로 받음

class QuestionsListAPIView(ListModelMixin, GenericAPIView):
    """피드 목록"""
    # TODO: 페이징 추가
    permission_classes = [AllowAny]
    queryset = Question.objects.all().order_by('-id')
    serializer_class = QuestionSerializer
    pagination_class = CustomPageNumberPagination  # 페이징 설정 추가
    page_size = 10
    max_page_size = 50

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def get(self, request, *args, **kwargs):
        return self.list(self, request, *args, **kwargs)

class QuestionAPIView(CreateModelMixin, GenericAPIView):
    """질문 등록"""
    queryset = Question.objects.all()
    serializer_class = QuestionCreateSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class QuestionsAPIView(UpdateModelMixin,
                       DestroyModelMixin,
                       GenericAPIView):
    """질문 수정 / 삭제"""
    # TODO: 빨리하면 넣는걸로 
    # TODO: Permission 수정
    permission_classes = [AllowAny]
    queryset = Question.objects.all()
    serializer_class = QuestionCreateSerializer
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def put(self, request, *args, **kwargs):
        """수정 기능 넣기로 했었나요...?"""
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        """질문 삭제"""
        return self.destroy(request, *args, **kwargs)


class AnswerAPIView(CreateModelMixin,
                       GenericAPIView):
    """답변"""
    queryset = Answer.objects.all()
    serializer_class = AnswerSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class Report(CreateModelMixin, GenericAPIView):
    """신고하기"""

    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class LikeView(CreateModelMixin, GenericAPIView):
    """좋아요 기능: 토글 방식으로 동작"""

    queryset = Like.objects.all()
    serializer_class = LikeSerializer
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def post(self, request, *args, **kwargs):
        user_id = request.user.social_id
        question_id = self.kwargs["pk"]

        liked = self.get_queryset().filter(
            question_id=question_id,
            user_id=user_id
        )

        if liked.exists():
            liked.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)

        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class Block(CreateModelMixin, GenericAPIView):
    """해당 게시글 사용자 차단하기: 추후에 user_id 기준으로만 요청하는 것으로 바꾸고 따로 빼도 될 것 같아요"""

    queryset = Block.objects.all()
    serializer_class = BlockSerializer
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)
