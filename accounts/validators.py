from django.forms import ValidationError
from accounts.models import User

def email_validator_for_login(email: str):
    email_exists = User.objects.filter(email = email).first()

    if not email_exists:
        raise ValidationError('User with this email does not exist.')

def email_validator_for_register(email: str):
    email_exists = User.objects.filter(email = email).first()
    
    if email_exists:
        raise ValidationError('User with this email already exists.')

def is_email(email: str):
    if not email.endswith('@gmail.com'):
        raise ValidationError('Please enter a valid email.')
