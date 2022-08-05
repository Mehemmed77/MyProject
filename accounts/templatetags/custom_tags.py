from django import template

register = template.Library()

@register.simple_tag
def find_icon(value):
    icons = {
        'username':'user',
        'email':'at',
        'password':'unlock-keyhole',
        'password2':'unlock-keyhole',
        'old_password':'unlock-keyhole',
        'new_password1':'unlock-keyhole',
        'new_password2':'unlock-keyhole',
        'bio':'align-left',
    }

    return icons.get(value)