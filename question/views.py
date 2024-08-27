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
from users.models import UserModel
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
from project.utils import custom_response 


class CustomPageNumberPagination(PageNumberPagination):
    page_size_query_param = 'page_size'  # 페이지당 보여질 아이템 수를 파라미터로 받음

    def get_paginated_response(self, data):
        return custom_response(
            data={
                'count': self.page.paginator.count,
                'next': self.get_next_link(),
                'previous': self.get_previous_link(),
                'results': data
            }
        )


class QuestionsListAPIView(ListModelMixin, GenericAPIView):
    """피드 목록"""
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

    def get_queryset(self):
        queryset = super().get_queryset()

        job_type = self.request.query_params.get('job')

        if job_type:
            queryset = queryset.filter(
                user_id__in=UserModel.objects.filter(job=job_type).values_list('social_id', flat=True))

        generation = self.request.query_params.get('generation')

        if generation:
            queryset = queryset.filter(
                user_id__in=UserModel.objects.filter(generation=generation).values_list('social_id', flat=True))

        sort_by = self.request.query_params.get('sort_by')

        if sort_by:
            if sort_by == 'oldest':
                queryset = queryset.order_by("created_at")
        else:
            queryset = queryset.order_by('-create_at')

        return queryset

    def get(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)

        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return custom_response(
            data=serializer.data
        )


class MyQuestionsListAPIView(ListModelMixin, GenericAPIView):
    """피드 목록"""
    queryset = Question.objects.all().order_by('-id')
    serializer_class = QuestionSerializer
    pagination_class = CustomPageNumberPagination  # 페이징 설정 추가
    page_size = 10
    max_page_size = 50

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(
            user_id=self.request.user.social_id)

    def get(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)

        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return custom_response(
            data=serializer.data
        )


class QuestionAPIView(CreateModelMixin, GenericAPIView):
    """질문 등록"""
    queryset = Question.objects.all()
    serializer_class = QuestionCreateSerializer

    BAD_WORDS = ['비속어1', '비속어2', '비속어3']

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def contains_bad_words(self, text):
        for bad_word in self.BAD_WORDS:
            if bad_word in text:
                return True
        return False

    def post(self, request, *args, **kwargs):
        question_text = request.data.get('title', '')

        if self.contains_bad_words(question_text):
            return custom_response(data={"status": True, "message": "질문에 비속어가 포함되어 있습니다."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response = self.create(request, *args, **kwargs)
        return custom_response(
            data=response.data
        )

class QuestionsAPIView(UpdateModelMixin, DestroyModelMixin, GenericAPIView):
    """질문 수정 / 삭제"""
    permission_classes = [AllowAny]
    queryset = Question.objects.all()
    serializer_class = QuestionCreateSerializer
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def put(self, request, *args, **kwargs):
        response = self.update(request, *args, **kwargs)
        return custom_response(
            data=response.data
        )

    def delete(self, request, *args, **kwargs):
        response = self.destroy(request, *args, **kwargs)
        return custom_response(
            data=response.data
        )


class AnswerAPIView(CreateModelMixin, GenericAPIView):
    """답변"""
    queryset = Answer.objects.all()
    serializer_class = AnswerSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def post(self, request, *args, **kwargs):
        response = self.create(request, *args, **kwargs)
        return custom_response(
            data=response.data
        )


class Report(CreateModelMixin, GenericAPIView):
    """신고하기"""

    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def post(self, request, *args, **kwargs):
        response = self.create(request, *args, **kwargs)
        return custom_response(
            data=response.data
        )


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
            return custom_response(
            )

        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            return custom_response(
                data=serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )

        self.perform_create(serializer)
        return custom_response(
            data=serializer.data,
            status=status.HTTP_201_CREATED
        )


class Block(ListModelMixin, CreateModelMixin, GenericAPIView):
    """해당 게시글 사용자 차단하기"""

    queryset = Block.objects.all()
    serializer_class = BlockSerializer
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context
    
    def get(self, request, *args, **kwargs):
        response = self.list(request, *args, **kwargs)
        return custom_response(
            data=response.data
        )

    def post(self, request, *args, **kwargs):
        response = self.create(request, *args, **kwargs)
        return custom_response(
            data=response.data
        )


class AdminQuestionListAPIView(ListModelMixin, GenericAPIView):
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

    def get_queryset(self):
        queryset = super().get_queryset()

        job_type = self.request.query_params.get('job')
        if job_type:
            queryset = queryset.filter(
                user_id__in=UserModel.objects.filter(job=job_type).values_list('social_id', flat=True))

        generation = self.request.query_params.get('generation')
        if generation:
            queryset = queryset.filter(
                user_id__in=UserModel.objects.filter(generation=generation).values_list('social_id', flat=True))

        sort_by = self.request.query_params.get('sort_by')
        if sort_by:
            if sort_by == 'oldest':
                queryset = queryset.order_by("created_at")
        else:
            queryset = queryset.order_by('-create_at')

        return queryset

    def get(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return custom_response(
            data=serializer.data
        )
