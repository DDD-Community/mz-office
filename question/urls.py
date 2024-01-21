from django.urls import path
from .views import Questions, Question, Report, Like, Block

urlpatterns = [
    path('questions/', Questions.as_view(), name='Questions'),
    path('question/', Question.as_view(), name='Question'),
    path('report/', Report.as_view(), name='Report'),
    path('like/', Like.as_view(), name='Like'),
    path('Block/', Block.as_view(), name='Block'),
]
