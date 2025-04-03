from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, get_user_model
from .serializers import UserSerializer
from django.http import JsonResponse
import logging

User = get_user_model()
logger = logging.getLogger(__name__)

def welcome_view(request):
    return JsonResponse({"message": "Welcome to the Django API!"})

# Signup with token response & logging
class SignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        user = User.objects.get(email=response.data["email"])
        refresh = RefreshToken.for_user(user)
        
        logger.info(f"User signed up: {user.email}")
        
        return Response(
            {
                "message": "User created successfully",
                "user": response.data,
                "access": str(refresh.access_token),
                "refresh": str(refresh)
            },
            status=201
        )

# Login - No token, just checking if user exists & logging
class LoginView(generics.GenericAPIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        
        user = authenticate(email=email, password=password)
        if user is not None:
            logger.info(f"User logged in: {user.email}")
            return Response({"message": "Login successful"}, status=200)
        else:
            logger.warning(f"Failed login attempt for email: {email}")
            return Response({"error": "Invalid credentials"}, status=400)

# Get Profile
class ProfileView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

# Logout
class LogoutView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            logger.info(f"User logged out: {request.user.email}")

            return Response({"message": "Logged out successfully"}, status=200)
        except:
            return Response({"error": "Invalid token"}, status=400)

# Delete Account
class DeleteAccountView(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        user = request.user
        logger.info(f"User deleted account: {user.email}")
        user.delete()
        return Response({"message": "Account deleted successfully"}, status=200)
