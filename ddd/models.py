# app/models.py

from django.db import models
from django.utils import timezone

class Notification(models.Model):
    position = models.CharField(max_length=50)
    support_path = models.CharField(max_length=50)
    name = models.CharField(max_length=50)
    email = models.EmailField()
    create_time = models.DateTimeField(default=timezone.now)
    email_sent = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.name} - {self.position}"