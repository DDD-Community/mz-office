from django.db import models


class Question(models.Model):
    """질문"""
    user_id = models.CharField(max_length=100, verbose_name='소셜사용자_id')
    emoji = models.IntegerField()
    title = models.CharField(max_length=255)
    # question_a = models.CharField(max_length=1, null=True)
    # question_b = models.CharField(max_length=1, null=True)
    choice_a = models.CharField(max_length=20, null=True)
    choice_b = models.CharField(max_length=20, null=True)
    delete_yn = models.CharField(max_length=1, default='N')
    create_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title  # 변경: text 대신 title을 반환하도록 수정


class Answer(models.Model):
    """질문에 포함된 답변 결과 테이블"""
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    user_id = models.CharField(max_length=100, verbose_name='소셜사용자_id')
    user_choice = models.CharField(max_length=1, null=True, verbose_name='사용자 응답')

    def __str__(self):
        return f"Answer to {self.question.title}"


class Report(models.Model):
    """신고 기록 테이블 (Question 단위)"""
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    user_id = models.CharField(max_length=100, verbose_name='소셜사용자_id')
    reason = models.CharField(max_length=255)
    create_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Report on {self.question.title} by {self.user_id}"


class Like(models.Model):
    """좋아요 테이블 (Question 단위)"""
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    user_id = models.CharField(max_length=100, verbose_name='소셜사용자_id')
    create_at = models.DateTimeField(auto_now_add=True)


class Block(models.Model):
    """차단 기록 테이블(UserModel 단위)"""
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    user_id = models.CharField(max_length=100, verbose_name='차단하는 사용자')
    blocked_user_id = models.CharField(max_length=100, verbose_name='차단된 사용자')
    create_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Block on {self.blocked_user_id} by {self.user_id}"
