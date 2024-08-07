# Generated by Django 4.2.9 on 2024-08-09 08:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0006_remove_userwithdrawalreason_user_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Block',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('question', models.IntegerField(null=True, verbose_name='차단 한 게시글')),
                ('user_id', models.CharField(max_length=100, verbose_name='차단하는 사용자')),
                ('blocked_user_id', models.CharField(max_length=100, verbose_name='차단된 사용자')),
                ('block_yn', models.CharField(default='Y', max_length=2, verbose_name='Y: 차단, N: 차단해제')),
                ('create_at', models.DateTimeField(auto_now_add=True)),
                ('update_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
