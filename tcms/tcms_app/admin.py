from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Role

# Register Role Model
@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('id', 'role_name')  # Display fields in admin panel
    search_fields = ('role_name',)  # Enable search by role name
    ordering = ('id',)


# Extend UserAdmin to include custom fields
@admin.register(User)
class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (  # Add custom fields to admin panel
        ('Additional Info', {'fields': ('role', 'profile_picture', 'status')}),
    )
    
    add_fieldsets = UserAdmin.add_fieldsets + (  # Fields shown when adding a new user
        ('Additional Info', {'fields': ('role', 'profile_picture', 'status')}),
    )

    list_display = ('username', 'email', 'role', 'status', 'is_staff', 'is_superuser')
    search_fields = ('username', 'email', 'role__role_name')
    list_filter = ('role', 'status', 'is_staff', 'is_superuser')
