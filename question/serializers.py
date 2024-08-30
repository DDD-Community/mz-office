# serializers.py
from rest_framework import serializers
from .models import Question, Report, Like, Answer, Block
from users.models import UserModel
from django.core.exceptions import ValidationError


class AnswerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Answer


class QuestionSerializer(serializers.ModelSerializer):
    """질문 목록 조회"""
    like_count = serializers.SerializerMethodField()
    report_count = serializers.SerializerMethodField()
    answer_count = serializers.SerializerMethodField()
    answer_ratio = serializers.SerializerMethodField()
    user_info = serializers.SerializerMethodField()
    metadata = serializers.SerializerMethodField()

    def get_user_info(self, obj):
        user_id = obj.user_id
        try:
            user = UserModel.objects.get(social_id=user_id)
            return {
                'user_id': user.social_id,
                'user_nickname': user.nickname,
                'user_job': user.job,
                'user_generation': user.generation,
            }
        except UserModel.DoesNotExist:
            return None

    def get_like_count(self, obj):
        return Like.objects.filter(question=obj).count()

    def get_report_count(self, obj):
        return Report.objects.filter(question=obj).count()

    def get_answer_count(self, obj):
        return Answer.objects.filter(question=obj).count()

    def get_answer_ratio(self, obj):
        total_votes = Answer.objects.filter(question=obj).count()
        if total_votes == 0:
            return {'A': 0, 'B': 0}
        ratio_a = (Answer.objects.filter(question=obj, user_choice='A').count() / total_votes) * 100
        ratio_b = (Answer.objects.filter(question=obj, user_choice='B').count() / total_votes) * 100
        return {'A': ratio_a, 'B': ratio_b}
    
    def get_metadata(self, obj):
        """조회하는 유저의 투표 여부 / 좋아요 여부 등"""
        if self.context['request'].user.is_anonymous:
            return {
                "liked": False,
                "voted": False,
                "voted_to": None
            }

        liked = Like.objects.filter(question=obj, user_id=self.context['request'].user.social_id).exists()
        voted_to = Answer.objects.filter(question=obj, user_id=self.context['request'].user.social_id)
        if not voted_to.exists():
            return {
                "liked": liked,
                "voted": False,
                "voted_to": None
            }
        return {
            "liked": liked,
            "voted": True,
            "voted_to": voted_to.first().user_choice
        }

    class Meta:
        model = Question
        fields = [
            'id', 
            'user_info',
            'emoji', 
            'title', 
            'choice_a', 
            'choice_b',  
            'answer_count',
            'answer_ratio',
            'like_count', 
            'report_count',
            'metadata', 
            'create_at',
        ]
        ordering = ['-id']  # 정렬 순서를 지정


class QuestionCreateSerializer(serializers.ModelSerializer):
    """새로운 질문 등록"""

    def create(self, validated_data):
        validated_data['user_id'] = self.context['request'].user.social_id
        return super().create(validated_data)
    
    class Meta:
        model = Question
        fields = [
            'id',
            'user_id',
            'emoji',
            'title',
            'choice_a',
            'choice_b',
            'create_at',
            'update_at',
        ]
        read_only_fields = (
            'id',
            'user_id',
            'create_at',
            'update_at',
        )


class AnswerSerializer(serializers.ModelSerializer):
    def create(self, validated_data):
        user_id = self.context['request'].user.social_id
        question_id = self.context['view'].kwargs["pk"]
        answer = Answer.objects.filter(user_id=user_id, question_id=question_id)

        if answer.exists():
            raise ValidationError("User already answered")

        validated_data['user_id'] = user_id
        validated_data['question_id'] = question_id
        validated_data['user_choice'] = validated_data['user_choice'].lower()
        return super().create(validated_data)

    class Meta:
        model = Answer
        fields = [
            'id',
            'question',
            'user_id',
            'user_choice',
        ]
        read_only_fields = (
            'id',
            'question',
            'user_id',
        )


class ReportSerializer(serializers.ModelSerializer):
    def create(self, validated_data):
        validated_data['user_id'] = self.context['request'].user.social_id
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
        validated_data['user_id'] = self.context['request'].user.social_id
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
        validated_data['user_id'] = self.context['request'].user.social_id
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
