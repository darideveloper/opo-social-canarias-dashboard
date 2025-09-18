from django.contrib import admin

from users import models


@admin.register(models.Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "last_pass",
        "profile_img",
        "created_at",
        "updated_at",
    )

    search_fields = ("user__username", "user__email")
    list_filter = ("created_at", "updated_at")
    ordering = ("-created_at",)
    list_per_page = 50
    date_hierarchy = "created_at"


@admin.register(models.TempToken)
class TempTokenAdmin(admin.ModelAdmin):
    list_display = ("profile", "token", "type", "is_active", "created_at", "updated_at")

    search_fields = ("profile__user__username", "profile__user__email")
    list_filter = ("type", "is_active", "created_at", "updated_at")
    ordering = ("-created_at",)
    list_per_page = 50
    date_hierarchy = "created_at"
