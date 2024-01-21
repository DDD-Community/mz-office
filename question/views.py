from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response

from .models import Question

# 질문 목록
class Questions(APIView):
    # 질문 리스트, 이모지 고민
    def get(self, request, format=None):
        # 좋아요 히스토리와 함께 조인, 블랙 리스트도 제외 필요
        question = Question.objects.all().order_by('-id')
        return Response(question)

# 질문 등록, 수정, 삭제
class Question(APIView):
    # 질문 등록
    def post(self, request, format=None):
        # TODO 질문 작성 시 답변 테이블 같이 받기
        data = {
            "id": 2,
            "name": "nayoung0",
            "age": 29,
            "city": "Gwanak-gu"
        }
        return Response(data)

    # 질문 수정
    def put(self, request, format=None):
        data = {
            "id": 2,
            "name": "nayoung0",
            "age": 29,
            "city": "Gwanak-gu"
        }
        return Response(data)

    # 질문 삭제
    def delete(self, request, format=None):
        data = {
            "id": 2,
            "name": "nayoung0",
            "age": 29,
            "city": "Gwanak-gu"
        }
        return Response(data)

# 신고하기
class Report(APIView):
    def post(self, request, format=None):
        data = {
            "id": 2,
            "name": "nayoung0",
            "age": 29,
            "city": "Gwanak-gu"
        }
        return Response(data)

# 좋아요
class Like(APIView):
    def post(self, request, format=None):
        data = {
            "id": 2,
            "name": "nayoung0",
            "age": 29,
            "city": "Gwanak-gu"
        }
        return Response(data)
    
# 블랙
class Block(APIView):
    def post(self, request, format=None):
        data = {
            "id": 2,
            "name": "nayoung0",
            "age": 29,
            "city": "Gwanak-gu"
        }
        return Response(data)
    
    