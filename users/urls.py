from django.urls import path

from users import views

urlpatterns = [
    path("me/", views.UserMeView.as_view(), name="user_me"),
]