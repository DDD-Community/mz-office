# Generated by Django 4.2.9 on 2024-08-14 00:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('question', '0008_remove_answer_select_question_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='question',
            name='choice_a',
            field=models.CharField(max_length=20, null=True),
        ),
        migrations.AlterField(
            model_name='question',
            name='choice_b',
            field=models.CharField(max_length=20, null=True),
        ),
    ]
