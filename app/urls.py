from django.urls import path
from app.views import OnePersonAPIView, TwoPersonAPIView

urlpatterns = [
    path('sample/', OnePersonAPIView.as_view(), name='one_person_api'),
    path('sample2/', TwoPersonAPIView.as_view(), name='two_person_api'),
]
