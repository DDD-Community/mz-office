from django.contrib import admin
from .models import Question, Answer, Report, Like, Block

admin.site.register(Question)
admin.site.register(Answer)
admin.site.register(Report)
admin.site.register(Like)
admin.site.register(Block)
