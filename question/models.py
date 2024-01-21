from django.db import models

# 질문 테이블
class Question(models.Model):
    user_id = models.IntegerField()
    emoji = models.IntegerField()
    title = models.CharField(max_length=255)
    delete_yn = models.CharField(max_length=1, default='N')
    create_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.title  # 변경: text 대신 title을 반환하도록 수정

# 질문에 포함 된 답변 선택 테이블
class Answer(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    user_id = models.IntegerField()

    def __str__(self):
        return f"Answer to {self.question.title}"

# 질문 신고 기록 테이블
class Report(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    user_id = models.IntegerField()
    reason = models.CharField(max_length=255)
    create_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Report on {self.question.title} by {self.user_id}"

# 질문 좋아요 기록 테이블
class Like(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    user_id = models.IntegerField()
    create_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Like on {self.question.title} by {self.user_id}"

# 블랙 기록 테이블
class Block(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    user_id = models.IntegerField()
    blocked_user_id = models.IntegerField()
    create_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Block on {self.blocked_user_id} by {self.user_id}"
