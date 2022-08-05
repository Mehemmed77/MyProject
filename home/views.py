from django.shortcuts import render
from django.views.generic import TemplateView


class IndexView(TemplateView):
    template_name = 'index.html'

class ReportSiteView(TemplateView):
    template_name = 'report-site.html'

class OnHoldView(TemplateView):
    template_name = 'onhold.html'

class SpecialsView(TemplateView):
    template_name = 'specials.html'

class AttackerView(TemplateView):
    template_name = 'activist-hackers.html'

class TopView(TemplateView):
    template_name = 'top20.html'

class BlogView(TemplateView):
    template_name = 'blog.html'

class ContactView(TemplateView):
    template_name = 'contact.html'
