from django.contrib import admin
from .models import URLCheck

from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('id', 'username', 'email', 'user_type', 'is_staff', 'is_active')
    list_display_links = ('username', 'email')  # 👈 these fields will be clickable
    list_filter = ('user_type', 'is_staff', 'is_active')
    
    fieldsets = UserAdmin.fieldsets + (
        ('User Type', {'fields': ('user_type',)}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('User Type', {'fields': ('user_type',)}),
    )

admin.site.register(CustomUser, CustomUserAdmin)


@admin.register(URLCheck)
class URLCheckAdmin(admin.ModelAdmin):
    list_display = ('url', 'result', 'score', 'user', 'created_at')
    list_filter = ('result', 'created_at')
    search_fields = ('url',)
