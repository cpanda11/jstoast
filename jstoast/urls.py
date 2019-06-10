"""jstoast URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from rest_framework.documentation import include_docs_urls

from jta.views import *

admin.site.site_header = 'JsToAst admin'
admin.site.site_title = 'Js to Ast conversion admin'
admin.site.index_title = 'JsToAst administration'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/scriptparse', ScriptParseViewSet.as_view()),
    path('api/astparse', AstParseViewSet.as_view()),
    path('docs/', include_docs_urls(title='JsToAst API')),
    path('api/genscript', GenerateNewJs.as_view()),
    path('api/rebuildml', RebuildMLViewSet.as_view()),
]
