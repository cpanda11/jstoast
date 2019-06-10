from django.contrib import admin
from .models import *


class ScriptParseAdmin(admin.ModelAdmin):
    list_display = ['id', 'input_js', 'output_ast']
    list_per_page = 20
    actions = None


admin.site.register(ScriptParse, ScriptParseAdmin)