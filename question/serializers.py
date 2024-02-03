# serializers.py
from rest_framework import serializers
from .models import Question, Report, Like, Answer, Block


class AnswerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Answer


class QuestionSerializer(serializers.ModelSerializer):
    """질문 목록 조회"""
    like_count = serializers.SerializerMethodField()
    report_count = serializers.SerializerMethodField()
    user_voted = serializers.SerializerMethodField()
    answer_count = serializers.SerializerMethodField()
    answer_ratio = serializers.SerializerMethodField()

    # TODO: 응답 카운트 추가 

    class Meta:
        model = Question
        fields = [
            'id', 
            'user_id', 
            'emoji', 
            'title', 
            'user_voted', 
            'question_a', 
            'question_b',  
            'answer_count',
            'answer_ratio',
            'like_count', 
            'report_count', 
            'create_at',
        ]
        ordering = ['-id']  # 정렬 순서를 지정

    def get_like_count(self, obj):
        return Like.objects.filter(question=obj).count()

    def get_report_count(self, obj):
        return Report.objects.filter(question=obj).count()

    def get_user_voted(self, obj):
        # user_id = self.context['request'].user.social_id  # 현재 요청한 사용자의 ID를 가져옴
        # TODO: 실제 유저로 변경
        user_id = 'random_user_1'
        if user_id:
            return Answer.objects.filter(question=obj, user_id=user_id).exists()
        return False

    def get_answer_count(self, obj):
        return Answer.objects.filter(question=obj).count()

    def get_answer_ratio(self, obj):
        if self.get_user_voted(obj):
            total_votes = Answer.objects.filter(question=obj).count()
            ratio_a = (Answer.objects.filter(question=obj, select_question='0').count() / total_votes) * 100
            ratio_b = (Answer.objects.filter(question=obj, select_question='1').count() / total_votes) * 100
            return {'0': ratio_a, '1': ratio_b}
        return None


class QuestionCreateSerializer(serializers.ModelSerializer):
    """새로운 질문 등록"""

    def create(self, validated_data):
        # TODO: 실제 유저로 변경
        validated_data['user_id'] = 'random_user_1'

        return super().create(validated_data)
    
    class Meta:
        model = Question
        fields = [
            'id',
            'user_id',
            'emoji',
            'title',
            'question_a',
            'question_b',
            'create_at',
            'update_at',
        ]
        read_only_fields = (
            'id',
            'user_id',
            'create_at',
            'update_at',
        )


class ReportSerializer(serializers.ModelSerializer):
    def create(self, validated_data):
        # TODO: 실제 유저로 변경
        validated_data['user_id'] = 'random_user_1'
        validated_data['question_id'] = self.context['view'].kwargs["pk"]
        return super().create(validated_data)
    
    class Meta:
        model = Report
        fields = [
            'id',
            'question',
            'user_id',
            'reason',
            'create_at',
        ]
        read_only_fields = (
            'id',
            'question',
            'user_id',
            'create_at',
        )


class LikeSerializer(serializers.ModelSerializer):
        
    def create(self, validated_data):
        # TODO: 실제 유저로 변경
        validated_data['user_id'] = 'random_user_1'
        question_id = self.context['view'].kwargs["pk"]
        
        question = Question.objects.get(id=question_id)
        validated_data['question'] = question
        return super().create(validated_data)
    
    class Meta:
        model = Like
        fields = [
            'question',
            'user_id',
            'create_at',
        ]
        read_only_fields = (
            'question',
            'user_id',
            'create_at',
        )

   
class BlockSerializer(serializers.ModelSerializer):
    
    # TODO: get_or_create 으로 변경
    def create(self, validated_data):
        # TODO: 실제 유저로 변경
        validated_data['user_id'] = 'random_user_1'
        validated_data['blocked_user_id'] = 'random_user_2'
        
        question_id = self.context['view'].kwargs["pk"]
        question = Question.objects.get(id=question_id)
        validated_data['question'] = question
        
        return super().create(validated_data)
    
    class Meta:
        model = Block
        fields = [
            'question',
            'user_id',
            'blocked_user_id',
            'create_at',
            'update_at',
        ]
        read_only_fields = (
            'question',
            'user_id',
            'blocked_user_id',
            'create_at',
            'update_at',
        )