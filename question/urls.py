from django.urls import path
from .views import QuestionsListAPIView, QuestionAPIView, Report, Like, Block

urlpatterns = [
    path('questions/', QuestionsListAPIView.as_view(), name='Questions'),
    path('question/', QuestionAPIView.as_view(), name='Question'),
    path('report/', Report.as_view(), name='Report'),
    path('like/', Like.as_view(), name='Like'),
    path('block/', Block.as_view(), name='Block'),
]
