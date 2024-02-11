from django.urls import path

from .views import *


urlpatterns = [
    path('kakao/login/', KakaoLoginView.as_view()),
    path('kakao/login/callback/', KakaoCallbackView.as_view()),

    path('google/login/', GoogleLoginView.as_view()),
    path('google/login/callback/', GoogleCallbackView.as_view()),

    path('apple/login/', AppleLoginView.as_view()),
    path('apple/login/callback/', AppleCallbackView.as_view()),
    path('apple/endpoint/', AppleEndpoint.as_view()),
]