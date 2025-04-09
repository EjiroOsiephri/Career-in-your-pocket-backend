

from rest_framework import generics, permissions, status
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



import os
import re
import requests
from urllib.parse import urlparse, parse_qs

from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import CareerAdviceHistory
import logging

logger = logging.getLogger(__name__)


class CareerAdviceView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_input = request.data.get("input", "")
        dropdowns = request.data.get("dropdowns", {})

        if not user_input and not dropdowns:
            return Response({"error": "Input or dropdowns are required"}, status=400)

        dropdown_string = "\n".join(
            [f"{key.replace('_', ' ').title()}: {value}" for key, value in dropdowns.items()]
        )

        full_prompt = f"{dropdown_string}\n\nUser Input: {user_input}\n\nPlease provide a career roadmap and recommend 2–3 relevant YouTube courses with links."

        # Call DeepSeek API
        response = self.get_deepseek_response(full_prompt)
        logger.debug(f"DeepSeek API Response: {response}")

        if isinstance(response, dict) and "error" in response:
            return Response(response, status=500)

        # Extract YouTube links and generate thumbnails
        youtube_links = self.extract_youtube_links(response)
        youtube_courses = [
            {
                "url": link,
                "thumbnail": self.get_youtube_thumbnail(link)
            }
            for link in youtube_links
        ]

        # Save query and response
        CareerAdviceHistory.objects.create(
            user=request.user, query=full_prompt, response=response
        )

        return Response({
            "career_advice": response,
            "recommended_courses": youtube_courses
        }, status=200)

    def get_deepseek_response(self, user_input):
        API_KEY = os.getenv("DEEPSEEK_API_KEY")
        API_URL = "https://api.deepseek.com/v1/chat/completions"

        if not API_KEY:
            logger.error("DeepSeek API key is not set")
            return {"error": "API key not configured"}

        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": "deepseek-chat",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a career assistant. Generate structured career roadmaps based on the user's background and goals."
                },
                {
                    "role": "user",
                    "content": f"{user_input}\n\nFormat:\n1. Career Title\n📌 Description: [Summary]\n🗺 Career Roadmap:\n✅ Step 1\n✅ Step 2\n✅ Step 3\n📚 Recommended YouTube Courses (with links):"
                }
            ],
            "temperature": 0.7,
            "max_tokens": 1500
        }

        try:
            logger.debug(f"Sending request to DeepSeek API")
            response = requests.post(API_URL, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            logger.debug(f"DeepSeek raw response: {data}")

            if "choices" not in data or not data["choices"]:
                logger.error("No valid choices in DeepSeek response")
                return {"error": "No valid choices returned by DeepSeek"}

            content = data["choices"][0].get("message", {}).get("content", "No response generated")
            return content or "No content in response"

        except requests.exceptions.RequestException as e:
            logger.error(f"DeepSeek request failed: {str(e)}")
            return {"error": f"API request failed: {str(e)}"}
        except ValueError as e:
            logger.error(f"DeepSeek response parse failed: {str(e)}")
            return {"error": "Invalid response format from API"}

    def extract_youtube_links(self, text):
        """
        Extract all YouTube links from the response text.
        """
        youtube_regex = r'(https?://(?:www\.)?(?:youtube\.com/watch\?v=|youtu\.be/)[^\s\)\]]+)'
        return re.findall(youtube_regex, text)

    def get_youtube_thumbnail(self, video_url):
        """
        Generate thumbnail URL for a given YouTube video.
        """
        parsed_url = urlparse(video_url)
        video_id = parse_qs(parsed_url.query).get('v')

        if video_id:
            video_id = video_id[0]
        else:
            # Handle youtu.be short URLs
            video_id = parsed_url.path.strip("/")

        return f"https://img.youtube.com/vi/{video_id}/hqdefault.jpg"



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
        access_token = request.data.get("access_token")

        if not access_token:
            return Response({"error": "Access token not provided"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Send a request to Google's User Info endpoint
            user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(user_info_url, headers=headers)

            # If the response is successful (status code 200)
            if response.status_code == 200:
                user_data = response.json()

                # Get the user's email and other info
                email = user_data["email"]
                first_name = user_data.get("given_name", "")
                last_name = user_data.get("family_name", "")

                # Check if the user exists, otherwise create a new one
                user, created = User.objects.get_or_create(
                    email=email,
                    defaults={"first_name": first_name, "last_name": last_name}
                )

                # Generate JWT token using simplejwt
                refresh = RefreshToken.for_user(user)

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

            else:
                return Response({"error": "Failed to fetch user info from Google"}, status=status.HTTP_400_BAD_REQUEST)

        except requests.exceptions.RequestException as e:
            return Response({"error": f"Error communicating with Google: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def put(self, request):
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            
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