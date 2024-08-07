from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser


class CustomUserManager(BaseUserManager):
    def _create_user(self, social_id, role=None, **extra_fields):
        if extra_fields.get('is_admin') is True:
            role = self.get_role(id=1, role_name='admin')
        else:
            role = self.get_role(id=2, role_name='user')

        user = self.model(social_id=social_id, role=role, **extra_fields)
        user.save(using=self._db)
        return user

    def get_role(self, id: int, role_name: str):
        role, _ = UserRoleModel.objects.get_or_create(id=id, name=role_name)
        return role

    def create_user(self, social_id, **extra_fields):
        extra_fields.setdefault('is_admin', False)

        return self._create_user(social_id, **extra_fields)

    def create_superuser(self, social_id, **extra_fields):
        extra_fields.setdefault('is_admin', True)

        if extra_fields.get('is_admin') is not True:
            raise ValueError('Superuser must have is_admin=True.')

        return self._create_user(social_id, **extra_fields)


class UserRoleModel(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=10)

    class Meta:
        managed = True
        db_table = 'user_role'
        app_label = 'users'
        verbose_name_plural = '사용자 권한'


class UserModel(AbstractBaseUser):
    social_id = models.CharField(max_length=100, primary_key=True, unique=True, verbose_name='소셜사용자_id')
    social_type = models.CharField(max_length=20, verbose_name='소셜 타입')
    email = models.EmailField(max_length=100, null=True, verbose_name='이메일')
    phone = models.CharField(max_length=13, unique=True, null=True, verbose_name='휴대폰 번호', help_text='ex) 010-0000-0000')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='가입일자')
    last_login = models.DateTimeField(blank=True, null=True, verbose_name='최근 로그인 일자')

    nickname = models.CharField(max_length=50, null=True, verbose_name='회원 닉네임')
    year = models.IntegerField(null=True, verbose_name='출생년도')
    job = models.CharField(max_length=50, null=True, verbose_name='직무')
    generation = models.CharField(max_length=50, null=True, verbose_name='시대')

    is_active = models.BooleanField(default=True, verbose_name='계정 활성화 여부')
    is_admin = models.BooleanField(default=False, verbose_name='관리자 여부')
    is_first_login = models.BooleanField(default=True, verbose_name='최초 로그인 여부')  # 추가된 필드

    role = models.ForeignKey(
        UserRoleModel, 
        related_name='user', 
        db_column='role_id', 
        on_delete=models.PROTECT, 
        verbose_name='사용자 권한'
    )
    
    objects = CustomUserManager()
    USERNAME_FIELD = 'social_id'
    password = None
    REQUIRED_FIELDS = []

    class Meta:
        managed = True
        db_table = 'users'
        app_label = 'users'
        verbose_name_plural = '회원정보'

    def save(self, *args, **kwargs):
        # Determine generation based on the year
        if self.year is not None:
            if 1955 <= self.year <= 1964:
                self.generation = "베이비붐 세대"
            elif 1965 <= self.year <= 1980:
                self.generation = "X 세대"
            elif 1981 <= self.year <= 1996:
                self.generation = "M 세대"
            elif 1997 <= self.year <= 2010:
                self.generation = "Z 세대"
            elif 2011 <= self.year <= 2024:
                self.generation = "알파 세대"
            else:
                self.generation = "기타 세대"

        super().save(*args, **kwargs)

class UserWithdrawalReason(models.Model):
    social_id = models.CharField(max_length=100, verbose_name='소셜사용자_id', null=False, default="")  # 외래 키 대신 소셜 ID를 직접 저장
    reason = models.TextField(verbose_name='탈퇴 사유')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='작성일자')

    class Meta:
        managed = True
        db_table = 'user_withdrawal_reasons'
        app_label = 'users'
        verbose_name_plural = '탈퇴 사유'

    def __str__(self):
        return f"{self.social_id} - {self.reason[:20]}"  # 소셜 ID와 사유 요약 출력
    
class Block(models.Model):
    """차단 기록 테이블(UserModel 단위)"""
    question = models.IntegerField(null=True, verbose_name='차단 한 게시글')
    user_id = models.CharField(max_length=100, verbose_name='차단하는 사용자')
    blocked_user_id = models.CharField(max_length=100, verbose_name='차단된 사용자')
    block_yn = models.CharField(max_length=2, verbose_name='Y: 차단, N: 차단해제', default='Y')
    create_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Block on {self.blocked_user_id} by {self.user_id}"
