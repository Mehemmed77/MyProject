from django.urls import path
from accounts.views import \
    RegisterView,ProfileView,Change_Password,SettingsView, \
    login_view,settings_view,digit_confirmation_view,type_email_and_set_digit_view,set_password,set_password_success

from django.contrib.auth.views import PasswordResetConfirmView

from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('login/',login_view,name = 'login'),
    path('register/',RegisterView.as_view(),name = 'register'),
    path('profile/<int:pk>/',ProfileView.as_view(),name = 'profile'),
    path('settings/<int:pk>',SettingsView.as_view(),name = 'settings'),
    path('logout/',LogoutView.as_view(),name = 'logout'),
    path('change-password/',Change_Password.as_view(),name = 'change-password'),
    path('type-email/',type_email_and_set_digit_view,name = 'type-email'),
    path('digit-confirmation/',digit_confirmation_view,name = 'digit-confirmation'),
    path('set-password/<str:token>/',set_password,name = 'set-password'),
    path('set-password-success/',set_password_success,name = 'set-password-success')


    # Reseting Password

    # Reseting Password
]