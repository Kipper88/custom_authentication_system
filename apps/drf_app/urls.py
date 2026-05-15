from django.urls import path

from apps.drf_app import views

urlpatterns = [
    path("auth/register/", views.RegisterView.as_view()),
    path("auth/login/", views.LoginView.as_view()),
    path("users/me/", views.MeView.as_view()),
    path("access/rules/", views.AccessRulesView.as_view()),
    path("business/documents/", views.DocumentsView.as_view()),
    path("business/reports/", views.ReportsView.as_view()),
]
