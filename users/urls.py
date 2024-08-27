from django.urls import path
from .views import *

app_name = 'users'

urlpatterns = [ 
    path('', MerberView.as_view(), name='user'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('jobs/', JobListAPIView.as_view(), name='job_list'),
    path('generation/', GenerationListAPIView.as_view(), name='generation_list'),
    path('nickname-check/', NicknameCheckAPIView.as_view(), name='nickname_check'),
    path('verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('block/', BlockUserView.as_view(), name='block_user'),
    path('blocks/', BlockListView.as_view(), name='block_list'),
    path('block/<str:blocked_user_id>/', UnblockUserView.as_view(), name='unblock_user'),
]
