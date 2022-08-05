from django import forms
from accounts.models import User
from django.contrib.auth.forms import PasswordChangeForm,SetPasswordForm
from accounts.validators import email_validator_for_login,email_validator_for_register,is_email

class TypeEmailForm(forms.Form):
    email = forms.EmailField(max_length = 60,required = True,
    validators = [is_email,email_validator_for_login],widget = forms.EmailInput(attrs={
        'class':'form-control',
        'placeholder':'Type your email',
    }))

class LoginForm(forms.ModelForm):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)

        email = self.fields['email']
        password = self.fields['password']

        email.widget = forms.EmailInput()
        email.required = True
        email.validators = [email_validator_for_login]

        password.widget = forms.PasswordInput()

        email.widget.attrs.update({
            'class':'form-control',
            'placeholder':'Enter Your Email',
        })

        password.widget.attrs.update({
            'class':'form-control',
            'placeholder':'Enter Your Password',
        })

    def clean_email(self):
        email = self.cleaned_data.get('email')

        if not email.endswith('@gmail.com'):
            raise forms.ValidationError('Enter a valid email address.')
        
        return email

    class Meta:
        model = User
        fields = ['email','password']

class RegisterForm(LoginForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args,**kwargs)

        self.fields['email'].validators = [email_validator_for_register]

        self.fields['username'].widget = forms.TextInput()

        self.fields['username'].widget.attrs.update({
            'class':'form-control',
            'placeholder':'Enter Your Username',
        })
    
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

    class Meta:
        model = User
        fields = ['username','email','password']
    
    password2 = forms.CharField(max_length = 50,required = True,widget = forms.PasswordInput(attrs = {
                'class':'form-control',
                'placeholder':'Confirm Your Password',
            }
        )
    )


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

    # def clean_new_password2(self):
    #     password1 = self.cleaned_data.get('new_password1')
    #     password2 = self.cleaned_data.get('new_password2')

    #     if password1!=password2:
    #         raise forms.ValidationError("Passwords don't match.")
        
    # def clean_new_password1(self):
    #     password1 = self.cleaned_data.get('new_password1')
    #     if len(password1)<8:
    #         raise forms.ValidationError('Minimum 8 characters.')
