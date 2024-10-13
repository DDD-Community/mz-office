# app/serializers.py

from rest_framework import serializers
from .models import Notification

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'position', 'support_path', 'name', 'email', 'create_time', 'email_sent']