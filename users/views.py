"use client";

from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, get_user_model
from .serializers import UserSerializer, CareerAdviceHistorySerializer
from django.http import JsonResponse
import requests
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
import os
from .models import CareerAdviceHistory
import logging
from google.auth.transport import requests as google_requests
from rest_framework_simplejwt.tokens import RefreshToken
from google.oauth2 import id_token
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags

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

        logger.debug(f"DeepSeek API Response: {response}")

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
        API_URL = "https://api.deepseek.com/v1/chat/completions"  # Updated to a more likely correct endpoint

        if not API_KEY:
            logger.error("DeepSeek API key is not set in environment variables")
            return {"error": "API key not configured"}

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
            logger.debug(f"Sending request to DeepSeek API: URL={API_URL}, Payload={payload}")
            response = requests.post(API_URL, headers=headers, json=payload)
            response.raise_for_status()  # Raises an HTTPError for bad responses (4xx, 5xx)
            response_data = response.json()
            logger.debug(f"Raw DeepSeek API Response: {response_data}")

            # Check the actual structure of the response
            if "choices" not in response_data or not response_data["choices"]:
                logger.error(f"Unexpected response structure: {response_data}")
                return "No valid choices in response"

            content = response_data["choices"][0].get("message", {}).get("content", "No response generated")
            return content if content else "No content in response"

        except requests.exceptions.RequestException as e:
            logger.error(f"DeepSeek API request failed: {str(e)}")
            return {"error": f"API request failed: {str(e)}"}
        except ValueError as e:
            logger.error(f"Failed to parse DeepSeek API response: {str(e)}")
            return {"error": "Invalid response format from API"}

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

        # Send Welcome Email
        subject = "Welcome to Pocket Career 🎉"
        html_message = render_to_string("welcome_email.html", {
            "first_name": user.first_name,
            "email": user.email,
            "token": str(refresh.access_token),
        })
        plain_message = strip_tags(html_message)

        try:
            send_mail(
                subject,
                plain_message,
                os.getenv("DEFAULT_FROM_EMAIL"),
                [user.email],
                html_message=html_message,
                fail_silently=False
            )
            logger.info(f"Welcome email sent to {user.email}")
        except Exception as e:
            logger.error(f"Email sending failed: {str(e)}")

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

class GoogleLoginView(APIView):
    def post(self, request):
        token_id = request.data.get("id_token")
        if not token_id:
            return Response({"error": "Token not provided"}, status=400)

        try:
            # Verify token using Google's public keys
            id_info = id_token.verify_oauth2_token(
                token_id,
                google_requests.Request(),
                audience=os.getenv("GOOGLE_CLIENT_ID")  # Make sure this is set
            )

            email = id_info["email"]
            first_name = id_info.get("given_name", "")
            last_name = id_info.get("family_name", "")

            user, created = User.objects.get_or_create(email=email, defaults={
                "first_name": first_name,
                "last_name": last_name,
                "username": email.split("@")[0],  # just in case
                "is_active": True
            })

            refresh = RefreshToken.for_user(user)

            logger.info(f"{'Created' if created else 'Logged in'} user via Google: {user.email}")

            return Response({
                "message": "Login successful",
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": {
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name
                }
            })

        except ValueError as e:
            logger.error(f"Google token verification failed: {str(e)}")
            return Response({"error": "Invalid token"}, status=400)


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

class ProfileView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

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

class DeleteAccountView(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        user = request.user
        logger.info(f"User deleted account: {user.email}")
        user.delete()
        return Response({"message": "Account deleted successfully"}, status=200)