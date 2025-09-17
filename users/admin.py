from django.contrib import admin

from users import models


@admin.register(models.Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "last_pass",
        "profile_img",
        "points",
        "created_at",
        "updated_at",
    )


@admin.register(models.TempToken)
class TempTokenAdmin(admin.ModelAdmin):
    list_display = ("profile", "token", "type", "is_active", "created_at", "updated_at")
