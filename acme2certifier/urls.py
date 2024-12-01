"""
URL configuration for acme2certifier project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  re_path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  re_path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  re_path('blog/', include('blog.urls'))
"""
# from django.contrib import admin
# from django.urls import path
#
# urlpatterns = [
#     re_path('admin/', admin.site.urls),
# ]


"""acme2certifier URL Configuration"""
# from django.conf.urls import include, url
from django.contrib import admin
from django.urls import re_path ,include
from acme_srv import views
from acme_srv.helper import load_config

# load config to set url_prefix
CONFIG = load_config()

# check ifwe need to prefix the url
if 'Directory' in CONFIG and 'url_prefix' in CONFIG['Directory']:
    PREFIX = CONFIG['Directory']['url_prefix'] + '/'
    if PREFIX.startswith('/'):
        PREFIX = PREFIX.lstrip('/')
else:
    PREFIX = ''

urlpatterns = [
    re_path(r'^admin/', admin.site.urls),
    re_path(r'^$', views.directory, name='index'),
    re_path(r'^directory$', views.directory, name='directory'),
    re_path(rf'^{PREFIX}get_servername$', views.servername_get, name='servername_get'),
    re_path(rf'^{PREFIX}trigger$', views.trigger, name='trigger'),
    re_path(rf'^{PREFIX}housekeeping$', views.housekeeping, name='housekeeping'),
    re_path(rf'^{PREFIX}acme/', include('acme_srv.urls'))
]

# check if we need to activate the url pattern for challenge verification
if 'CAhandler' in CONFIG and 'acme_url' in CONFIG['CAhandler']:
    urlpatterns.append(re_path(rf'^{PREFIX}.well-known/acme-challenge/', views.acmechallenge_serve, name='acmechallenge_serve'))

