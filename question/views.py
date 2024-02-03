from django.shortcuts import render
from django.core.serializers import serialize

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
    ReportSerializer,
    LikeSerializer,
    BlockSerializer,
)
from .models import (
    Question,
    Report,
    Like,
    Block,
)



class QuestionsListAPIView(ListModelMixin, GenericAPIView):
    """피드 목록"""
    # TODO: Permission 수정
    permission_classes = [AllowAny]
    queryset = Question.objects.all().order_by('-id')
    serializer_class = QuestionSerializer
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def get(self, request, *args, **kwargs):
        return self.list(self, request, *args, **kwargs)


class QuestionAPIView(CreateModelMixin, GenericAPIView):
    """질문 등록"""

    # TODO: Permission 수정
    permission_classes = [AllowAny]
    queryset = Question.objects.all()
    serializer_class = QuestionCreateSerializer

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class QuestionsAPIView(UpdateModelMixin,
                       DestroyModelMixin,
                       GenericAPIView):
    """질문 수정 / 삭제"""

    # TODO: Permission 수정
    permission_classes = [AllowAny]
    queryset = Question.objects.all()
    serializer_class = QuestionCreateSerializer

    def put(self, request, *args, **kwargs):
        """수정 기능 넣기로 했었나요...?"""
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        """삭제 기능은... 넣나요..?"""
        return self.destroy(request, *args, **kwargs)


class Report(CreateModelMixin, GenericAPIView):
    """신고하기"""

    # TODO: Permission 수정
    permission_classes = [AllowAny]
    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    
    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class LikeView(CreateModelMixin, GenericAPIView):
    """좋아요 기능: 토글 방식으로 동작"""

    # TODO: Permission 수정
    permission_classes = [AllowAny]
    queryset = Like.objects.all()
    serializer_class = LikeSerializer
    
    def post(self, request, *args, **kwargs):
        user_id = 'random_user_1'
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

    # TODO: Permission 수정
    permission_classes = [AllowAny]
    queryset = Block.objects.all()
    serializer_class = BlockSerializer
    

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)
