from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, get_user_model
from .serializers import UserSerializer
from django.http import JsonResponse
import requests
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
import os
from .models import CareerAdviceHistory
from .serializers import CareerAdviceHistorySerializer

import logging

User = get_user_model()

logger = logging.getLogger(__name__)

def welcome_view(request):
    return JsonResponse({"message": "Welcome to the Django API!"})


class CareerAdviceView(APIView):
    permission_classes = [IsAuthenticated] 


    def post(self, request):
        user_input = request.data.get("input", "")

        if not user_input:
            return Response({"error": "Input is required"}, status=400)

        # Call DeepSeek API
        response = self.get_deepseek_response(user_input)

        if "error" in response:
            return Response(response, status=500)

    
        CareerAdviceHistory.objects.create(
            user=request.user, query=user_input, response=response
        )

        return Response({"career_advice": response}, status=200)

    def get_deepseek_response(self, user_input):
        """
        Call DeepSeek API to generate career advice.
        """
        API_KEY = os.getenv("DEEPSEEK_API_KEY") 
        API_URL = "https://api.deepseek.com/generate"

        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": "You are a career assistant. Generate structured career roadmaps."},
                {"role": "user", "content": f"Give me a career roadmap for {user_input} in the format:\n1. Career Title\n📌 Description: [Summary]\n🗺 Career Roadmap:\n✅ Step 1\n✅ Step 2\n✅ Step 3"}
            ],
            "temperature": 0.7,
            "max_tokens": 500
        }

        try:
            response = requests.post(API_URL, headers=headers, json=payload)
            response_data = response.json()
            return response_data.get("choices", [{}])[0].get("message", {}).get("content", "No response generated")
        except Exception as e:
            return {"error": str(e)}    



class CareerHistoryView(generics.ListAPIView):
    serializer_class = CareerAdviceHistorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return CareerAdviceHistory.objects.filter(user=self.request.user).order_by("-created_at")


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
