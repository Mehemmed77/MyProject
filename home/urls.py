from django.urls import path
from home.views import IndexView, \
    ReportSiteView, OnHoldView, SpecialsView, \
    AttackerView, TopView, BlogView, ContactView

urlpatterns = [
    path('',IndexView.as_view(), name = 'index'),
    path('index/',IndexView.as_view(), name = 'index'),
    path('report/',ReportSiteView.as_view(), name = 'report'),
    path('archive/',OnHoldView.as_view(), name = 'archive'),
    path('specials/',SpecialsView.as_view(), name = 'special'),
    path('attacker/',AttackerView.as_view(), name = 'attacker'),
    path('top/',TopView.as_view(), name = 'top'),
    path('blog/',BlogView.as_view(), name = 'blog'),
    path('contact/',ContactView.as_view(), name = 'contact'),
]