from django.urls import path
from .views import (
    QuestionsListAPIView,
    MyQuestionsListAPIView,
    QuestionAPIView,
    QuestionsAPIView,
    AnswerAPIView,
    Report,
    LikeView,
    Block,
    AdminQuestionListAPIView
)

urlpatterns = [
    path('questions/', QuestionsListAPIView.as_view(), name='Questions'),
    path('questions/me/', MyQuestionsListAPIView.as_view(), name='Questions'),
    path('question/', QuestionAPIView.as_view(), name='Question'),
    path('question/<int:pk>/', QuestionsAPIView.as_view(), name='Question'),
    path('questions/<int:pk>/vote', AnswerAPIView.as_view(), name='Vote'),
    path('questions/<int:pk>/report/', Report.as_view(), name='Report'),
    path('questions/<int:pk>/like/', LikeView.as_view(), name='Like'),
    path('questions/<int:pk>/block/', Block.as_view(), name='Block'),

    path('back-office/questions/', AdminQuestionListAPIView.as_view(), name='')
]
