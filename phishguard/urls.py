from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from .import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('detector.urls')),
    path('base/', views.BASE, name='base'),
    path('Dashboard', views.Dashboard, name='dashboard'),
    path('AdminLogin', views.AdDMIN_LOGIN, name='admin_login'),
    path('AdminProfile', views.AdDMIN_PROFILE, name='admin_profile'),
    path('Profile/update', views.ADMIN_PROFILE_UPDATE, name='profile_update'),
    path('Password', views.CHANGE_PASSWORD, name='change_password'),
    path('doLogin', views.doLogin, name='doLogin'),
    path('doLogout', views.doLogout, name='logout'),
    path('ResetPassword', views.reset_password, name='reset_password'),
    path('RegisterUsers', views.registeres_users, name='registeres_users'),
    path('DeleteRegisteredUsers/<str:id>', views.DELETE_REGUSERS, name='delete_regusers'),
    path('user_urlcheck_history/<int:user_id>/', views.user_urlcheck_history, name='user_urlcheck_history'),
    path('Between_Date_Report', views.Between_Date_Report, name='between_date_report'),
    path('Search_URLCHECK', views.Search_URLCHECK, name='search_url_check'),
    path('checks/today/', views.today_checks, name='today_checks'),
    path('checks/yesterday/', views.yesterday_checks, name='yesterday_checks'),
    path('checks/seven-days/', views.seven_days_checks, name='seven_days_checks'),
    path('checks/month/', views.month_checks, name='month_checks'),
]+static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)
