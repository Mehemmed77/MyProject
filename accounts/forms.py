from django import forms
from accounts.models import User
from django.contrib.auth.forms import PasswordChangeForm,SetPasswordForm,AuthenticationForm
from accounts.validators import email_exists,email_not_exists,is_email

class TypeEmailForm(forms.Form):
    email = forms.EmailField(max_length = 60,required = True,
    validators = [is_email,email_exists],widget = forms.EmailInput(attrs={
        'class':'form-control',
        'placeholder':'Type your email',
    }))

class LoginForm(AuthenticationForm):
    username = forms.CharField(widget = forms.TextInput(
        attrs = {
            'class':'form-control',
            'placeholder':'Enter Your Username',
        }
    ))

    password = forms.CharField(widget = forms.PasswordInput(
        attrs = {
            'class':'form-control',
            'placeholder':'Enter Your Password'
        }
    ))


class RegisterForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username','email','password']

        widgets = {
            'username':forms.TextInput(attrs = {
                'class':'form-control',
                'placeholder':'Enter Your Username',
            }),

            'password':forms.PasswordInput(attrs = {
                'class':'form-control',
                'placeholder':'Enter Your Password',
                'minlength':'8'
            }),
        }

    email = forms.EmailField(max_length = 60,required = True,validators = [is_email,email_not_exists],
    widget = forms.EmailInput(attrs = {
        'class':'form-control',
        'placeholder':'Enter Your Email',
    }))

    password2 = forms.CharField(max_length = 50,min_length = 8,required = True,widget = forms.PasswordInput(attrs = {
                'class':'form-control',
                'placeholder':'Confirm Your Password',
            }
        )
    )

    def clean_password2(self):
        password1 = self.cleaned_data.get('password')
        password2 = self.cleaned_data.get('password2')

        if password1!=password2:
            raise forms.ValidationError("Passwords don't match.")
    
        return password2

    def save(self):
        username = self.cleaned_data.get('username')
        email = self.cleaned_data.get('email')
        password = self.cleaned_data.get('password')

        user = User.objects.create_user(username = username,email = email,password = password)

        return user


class SettingsForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['image','bio','username']

        widgets = {
            'image':forms.FileInput(attrs = {
                'onchange':'changeImage(event)'
            }),

            'bio':forms.TextInput(attrs = {
                'class':'form-control',
                'placeholder':'Your Bio'
            }),

            'username':forms.TextInput(attrs = {
                'class':'form-control',
                'placeholder':'username'
            }),
        }


class NewPassword(PasswordChangeForm):
    old_password = forms.CharField(label = 'Enter Your Old Password',
    widget = forms.PasswordInput(attrs = {
        'class':'form-control',
        'placeholder':'Old Password',
    }))

    new_password1 = forms.CharField(label = 'Enter Your New Password',
    widget = forms.PasswordInput(attrs = {
        'class':'form-control',
        'placeholder':'New Password',
    }))

    new_password2 = forms.CharField(label = 'Enter Your New Password Again',
    widget = forms.PasswordInput(attrs = {
        'class':'form-contorl',
        'placeholder':'Confirm New Password',
    }))

class SetPassword_Form(SetPasswordForm):
    new_password1 = forms.CharField(label = 'Enter Your New Password',
    widget = forms.PasswordInput(attrs = {
        'class':'form-control',
        'placeholder':'New Password',
    }))

    new_password2 = forms.CharField(label = 'Enter Your New Password Again',
    widget = forms.PasswordInput(attrs = {
        'class':'form-contorl',
        'placeholder':'Confirm New Password',
    }))

