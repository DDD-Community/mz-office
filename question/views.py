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
from django.db.models import Count

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


class QuestionStatsView(GenericAPIView):
    serializer_class = AnswerSerializer

    def get(self, request, *args, **kwargs):
        question_id = kwargs.get('pk')
        if not question_id:
            return custom_response(
                data={'error': 'Question ID is required.'},
                status=status.HTTP_404_NOT_FOUND
            )

        try:
            question = Question.objects.get(pk=question_id)
            total_votes = Answer.objects.filter(question=question).count()
            if total_votes == 0:
                return custom_response(
                    data={'error': 'No answers found for this question.'},
                    status=status.HTTP_404_NOT_FOUND
                )

            # 세대별 비율과 전체 비율을 계산
            answers = Answer.objects.filter(question=question).values('user_id', 'user_choice').annotate(
                count=Count('id')
            )
            user_ids = {answer['user_id'] for answer in answers}
            users = UserModel.objects.filter(social_id__in=user_ids)
            user_generation = {user.social_id: user.generation for user in users}

            answer_ratio = {'A': {}, 'B': {}}
            total_A = 0
            total_B = 0

            for answer in answers:
                user_gen = user_generation.get(answer['user_id'], 'Unknown')
                choice = answer['user_choice']
                count = answer['count']
                if choice == 'A':
                    total_A += count
                elif choice == 'B':
                    total_B += count
                percentage = (count / total_votes) * 100

                if user_gen not in answer_ratio[choice]:
                    answer_ratio[choice][user_gen] = percentage
                else:
                    answer_ratio[choice][user_gen] += percentage

                # 전체 A와 B 비율 계산
            total_ratio_A = (total_A / total_votes) * 100
            total_ratio_B = (total_B / total_votes) * 100
            overall_ratio = {'A': total_ratio_A, 'B': total_ratio_B}

            return custom_response(
                data={'id': question_id, 'stats': answer_ratio, 'overall_ratio': overall_ratio}
            )
        except Question.DoesNotExist:
            return custom_response(
                data={'error': 'Question not found.'},
                status=status.HTTP_404_NOT_FOUND
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

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def post(self, request, *args, **kwargs):
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
