from django.db import models
from django.contrib.auth.models import AbstractUser




class CustomUser(AbstractUser):
    USER_TYPES = (
        ('1', 'admin'),
        ('2', 'regusers'),
    )
    user_type = models.CharField(choices=USER_TYPES, max_length=10, default='1')

class URLCheck(models.Model):
    RESULT_CHOICES = (('legit', 'Legitimate'), ('phish', 'Phishing'))
    user = models.ForeignKey(CustomUser, null=True, blank=True, on_delete=models.SET_NULL)
    url = models.TextField()
    score = models.FloatField(default=0.0)
    result = models.CharField(max_length=10, choices=RESULT_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.url[:50]}... [{self.result}]"
