# Generated by Django 4.2.9 on 2024-01-27 05:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('question', '0003_answer_content'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='answer',
            name='content',
        ),
        migrations.AddField(
            model_name='answer',
            name='select_question',
            field=models.CharField(max_length=1, null=True),
        ),
        migrations.AddField(
            model_name='question',
            name='question_a',
            field=models.CharField(default='A', max_length=1, null=True),
        ),
        migrations.AddField(
            model_name='question',
            name='question_b',
            field=models.CharField(default='B', max_length=1, null=True),
        ),
    ]
