from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import SignupView, ProfileView, LogoutView, DeleteAccountView, CareerAdviceView, CareerHistoryView,GoogleLoginView

urlpatterns = [
    path("signup/", SignupView.as_view(), name="signup"),
    path("login/", TokenObtainPairView.as_view(), name="login"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("delete-account/", DeleteAccountView.as_view(), name="delete_account"),
    path("career-advice/", CareerAdviceView.as_view(), name="career-advice"),
    path("career-history/", CareerHistoryView.as_view(), name="career-history"),
    path("google/", GoogleLoginView.as_view(), name="google-login"),
]
