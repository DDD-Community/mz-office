# serializers.py
from rest_framework import serializers
from .models import Question, Report, Like, Answer

class QuestionSerializer(serializers.ModelSerializer):
    like_count = serializers.SerializerMethodField()
    report_count = serializers.SerializerMethodField()
    user_voted = serializers.SerializerMethodField()
    answer_ratio = serializers.SerializerMethodField()

    class Meta:
        model = Question
        fields = ['id', 'user_id', 'emoji', 'title', 'user_voted', 'question_a', 'question_b', 'answer_ratio', 'like_count', 'report_count', 'create_at']
        ordering = ['-id']  # 정렬 순서를 지정

    def get_like_count(self, obj):
        return Like.objects.filter(question=obj).count()

    def get_report_count(self, obj):
        return Report.objects.filter(question=obj).count()

    def get_user_voted(self, obj):
        user_id = self.context['request'].user.social_id  # 현재 요청한 사용자의 ID를 가져옴
        if user_id:
            return Answer.objects.filter(question=obj, user_id=user_id).exists()
        return False

    def get_answer_ratio(self, obj):
        if self.get_user_voted(obj):
            total_votes = Answer.objects.filter(question=obj).count()
            ratio_a = (Answer.objects.filter(question=obj, select_question='0').count() / total_votes) * 100
            ratio_b = (Answer.objects.filter(question=obj, select_question='1').count() / total_votes) * 100
            return {'0': ratio_a, '1': ratio_b}
        return None
