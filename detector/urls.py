from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('history/', views.history, name='history'),
    path('api/check/', views.api_check, name='api_check'),
    path('register/', views.register_user, name='register'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
]
