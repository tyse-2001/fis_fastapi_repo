from django.urls import path

from . import views

app_name = 'fastapi_table'
urlpatterns = [
    path('', views.search_page, name='search_page'),

    # Domain Ip
    path('domain_ip/', views.domain_ip_search, name='domain_ip_search'),
    path('domain_ip_get/', views.domain_ip_redirect, name='domain_ip_redirect'),
    path('domain_ip/<str:object_id>/', views.search_domain_ip, name='search_domain_ip'),

    # Files
    path('files/', views.files_search, name='files_search'),
    path('files_get/', views.files_redirect, name='files_redirect'),
    path('files/<str:file_id>/', views.search_files, name='search_files'),

    # Search
    #path('search/', views.search_page, name='search_page'),
]