from django import template

register = template.Library()

@register.filter
def percentage(value, arg):
    """Calculate percentage"""
    try:
        if int(arg) > 0:
            return int((int(value) / int(arg)) * 100)
        return 0
    except (ValueError, ZeroDivisionError):
        return 0