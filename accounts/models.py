from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    image = models.ImageField(upload_to = 'profile-pictures/',default = 'profile-pictures/default.jpg')
    bio = models.CharField(max_length = 40,default = "Hi i'm here.")

    def __str__(self):
        return self.username.title()
