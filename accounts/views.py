from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.contrib.auth import login
from django.urls import reverse_lazy
from django.views.generic import DetailView,UpdateView
from django.contrib.auth.views import PasswordChangeView,PasswordResetConfirmView,LoginView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import CreateView
from django.contrib.auth.hashers import check_password
from accounts.models import User
from random import randrange
from django.utils.crypto import get_random_string

# FORMS ------------
from accounts.forms import RegisterForm,LoginForm,SettingsForm,PasswordChangeForm,TypeEmailForm,SetPassword_Form

class MyLoginView(LoginView):
    template_name = 'auth/login.html'
    form_class = LoginForm

    def dispatch(self, request: HttpRequest, *args: tuple, **kwargs: dict):
        if request.user.is_authenticated:
            return redirect('index')

        return super().dispatch(request, *args, **kwargs)

    def form_invalid(self, form) -> HttpResponse:
        form.add_error(None,'Password or Username is incorrect.')

        next = self.request.GET.get('next')
        if next:
            self.request.GET.next = next

        return super().form_invalid(form)

class RegisterView(CreateView):
    template_name = 'auth/register.html'
    form_class = RegisterForm

    def get(self, request: HttpRequest, *args: tuple, **kwargs: dict) -> HttpResponse:
        if request.user.is_authenticated:
            return redirect('index')

        return super().get(request, *args, **kwargs)
    
    def form_valid(self, form) -> HttpResponse:
        user = form.save()
        login(self.request,user)

        return redirect('index')

class ProfileView(LoginRequiredMixin,DetailView):
    template_name = 'auth/profile.html'
    model = User
    context_object_name = 'profile_user'

class SettingsView(LoginRequiredMixin,UpdateView):
    template_name = 'auth/settings.html'
    model = User
    form_class = SettingsForm
    # success_url = reverse_lazy('index')

    def dispatch(self, request: HttpRequest, *args: tuple, **kwargs: dict):
        if self.kwargs['pk'] != request.user.id:
            raise Http404

        return super().dispatch(request, *args, **kwargs)

    def form_invalid(self, form) -> HttpResponse:
        errors = form.errors.as_data()
        
        for i in errors:
            errors[i] = list(list(errors[i])[0])[0]

        image = self.request.FILES.get('image')
        if image is not None:
            self.request.user.image = image
            self.request.user.save()

        copy_version = self.request.POST.copy()
        copy_version['username'] = self.request.user.username
        copy_version['email'] = self.request.user.email
        copy_version['bio'] = self.request.user.bio

        form = SettingsForm(copy_version,instance = self.request.user)

        return render(self.request,self.template_name,{'form':form,'form_errors':errors})

    def get_success_url(self) -> str:
        return reverse_lazy('settings',kwargs = {'pk':self.request.user.id})

# def settings_view(request: HttpRequest):

#     instance = request.user

#     if request.method == 'POST':
#         form = SettingsForm(request.POST,instance = instance)

#         image = request.FILES.get('image')

#         if image:
#             request.user.image = image
#             request.user.save()

#         if form.is_valid():
#             form.save()

#         else:
#             copy_version = request.POST.copy()
#             copy_version['username'] = request.user
#             form.data = copy_version

#     else:
#         form = SettingsForm(instance = instance)

#     context = {'form':form}

#     return render(request,'auth/settings.html',context = context)


class Change_Password(PasswordChangeView,LoginRequiredMixin):
    template_name = 'auth/password-change.html'
    form_class = PasswordChangeForm
    success_url = reverse_lazy('set-password-success')

    def dispatch(self, request: HttpRequest, *args: tuple, **kwargs: dict):
        if not request.user.is_authenticated:
            return redirect('type-email')

        return super().dispatch(request, *args, **kwargs)

    def form_invalid(self, form):
        return super().form_invalid(form)


def type_email_and_set_digit_view(request: HttpRequest):
    if request.user.is_authenticated:
        return redirect('index')

    if request.method == 'POST':
        form = TypeEmailForm(request.POST)

        if form.is_valid():
            email = form.cleaned_data.get('email')
            digit = randrange(100000,1000000)
            request.session['digit'] = digit
            request.session['attempts'] = 0
            request.session['email'] = email
            # send_mail('Reset Your Password',f'Type This Number 6 Digit Number To Reset Your Password',
            # settings.EMAIL_HOST_USER,[email])
            return redirect('digit-confirmation')

    else:
        form = TypeEmailForm()
    
    context = {'form':form}
    
    return render(request,'auth/type_email.html',context = context)

def digit_confirmation_view(request: HttpRequest):
    main_number = request.session.get('digit')
    error_msg = request.session.get('error_msg')

    print(main_number)
    
    if request.session.get('digit') is None:
        return redirect('type-email')

    if request.method == 'POST':
        l = [i for i in list(request.POST.values()) if i.isdigit()]
        number = int("".join(l))

        if number == main_number:
            for i in dict(request.session).copy():
                if i != 'email':
                    request.session.pop(i)
                
            token = get_random_string(32)
            request.session['token'] = token

            return redirect('set-password',token)
        
        else:
            error_msg = 'Failed Confirmation Please Try Again.'
            request.session['error_msg'] = error_msg
            request.session['attempts'] += 1
            
            if request.session['attempts'] == 3:
                request.session.clear()

                return redirect('set-password-error')

    context = {'error_msg':error_msg}

    return render(request,'auth/digit-confirmation.html',context = context)

def set_password(request: HttpRequest,token: str):
    if token != request.session.get('token'):
        raise Http404

    email = request.session.get('email')
    user = User.objects.get(email = email)

    if request.method == 'POST':
        form = SetPassword_Form(user,request.POST)
        if form.is_valid():
            form.save()

            login(request,user)
            request.session.clear()

            return redirect('set-password-success')

    else:
        form = SetPassword_Form(user)

    context = {'form':form}

    return render(request,'auth/setpassword.html',context = context)

def set_password_success(request: HttpRequest):
    return render(request,'auth/setpassword-success.html')

def set_password_error(request: HttpRequest):
    return render(request,'auth/setpassword-error.html')
