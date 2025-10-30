from django.db import models


class Profile(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.OneToOneField("auth.User", on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    profile_img = models.ImageField(upload_to='profile/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username}"

    class Meta:
        verbose_name = "Perfil"
        verbose_name_plural = "Perfiles"


class TempToken(models.Model):
    TYPE_CHOICES = (
        ('sign_up', 'Sign Up'),
        ('pass', 'Reset Password'),
    )

    id = models.AutoField(primary_key=True)
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE)
    token = models.CharField(max_length=16)
    type = models.CharField(max_length=10, choices=TYPE_CHOICES, default='sign_up')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.token}"
    
    class Meta:
        verbose_name = "Token Temporal"
        verbose_name_plural = "Tokens Temporales"