from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('domain_ip/', views.domain_ip_search, name='domain_ip_search'),
    path('get_name/', views.domain_ip_redirect, name='domain_ip_redirect'),
    path('domain_ip/<str:object_id>/', views.search_domain_ip, name='search_domain_ip'),
]