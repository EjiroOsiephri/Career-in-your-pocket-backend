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
from django.db import transaction
from rest_framework_simplejwt.tokens import RefreshToken
from google.oauth2 import id_token
from django.core.mail import send_mail

import requests
from urllib.parse import urlparse, parse_qs

from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
import logging
from django.template.loader import render_to_string
from django.utils.html import strip_tags


User = get_user_model()

logger = logging.getLogger(__name__)

def welcome_view(request):
    return JsonResponse({"message": "Welcome to the Django API!"})


class CareerAdviceView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user_input = request.data.get("input", "")
            dropdowns = request.data.get("dropdowns", {})
            logger.info(f"Received input: {user_input}")
            logger.info(f"Received dropdowns: {dropdowns}")

            if not user_input and not dropdowns:
                return Response({"error": "Input or dropdowns are required"}, status=400)

            # Improved prompt with more explicit formatting instructions
            full_prompt = f"""
User Request: {user_input}
Dropdown Selections: {dropdowns}

Please provide detailed career advice in this EXACT format:

**Career Title:** [Job Title Here]

📌 **Description:** 
[Detailed 2-3 paragraph description of this career path]

🗺 **Career Roadmap:**
✅ **Step 1:** [Step description]
✅ **Step 2:** [Step description] 
✅ **Step 3:** [Step description]

📚 **Recommended Courses:**
1. **Title:** [Course Name]
   - **Description:** [Course description]
   - **URL:** [Full course URL]
   - **Platform:** [Platform name]

2. **Title:** [Course Name]
   - **Description:** [Course description]
   - **URL:** [Full course URL]
   - **Platform:** [Platform name]

3. **Title:** [Course Name]
   - **Description:** [Course description]
   - **URL:** [Full course URL]
   - **Platform:** [Platform name]

Important Notes:
- Do NOT include any additional text before or after this format
- Use clean URLs without markdown formatting
- List exactly 3 courses
- Keep all information within the specified sections"""

            logger.info(f"Full prompt: {full_prompt}")

            # Get response from DeepSeek
            deepseek_response = self.get_deepseek_response(full_prompt)
            if isinstance(deepseek_response, dict) and "error" in deepseek_response:
                return Response(deepseek_response, status=500)

            logger.info(f"Raw DeepSeek response: {deepseek_response}")

            # Parse the response
            career_advice, recommended_courses = self.parse_response(deepseek_response)
            
            # Save to history (in a transaction to prevent timeouts)
            with transaction.atomic():
                CareerAdviceHistory.objects.create(
                    user=request.user,
                    query=full_prompt,
                    response=deepseek_response
                )

            response_data = {
                "career_advice": career_advice,
                "recommended_courses": recommended_courses
            }
            
            return Response(response_data, status=200)

        except Exception as e:
            logger.error(f"Error in CareerAdviceView: {str(e)}", exc_info=True)
            return Response({"error": "An error occurred processing your request"}, status=500)

    def get_deepseek_response(self, user_input):
        API_KEY = os.getenv("DEEPSEEK_API_KEY")
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
                    "content": "You are a career advisor. Provide detailed career guidance following the EXACT format specified."
                },
                {
                    "role": "user", 
                    "content": user_input
                }
            ],
            "temperature": 0.7,
            "max_tokens": 1500
        }

        try:
            response = requests.post(
                "https://api.deepseek.com/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=30  # Add timeout
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"DeepSeek API error: {str(e)}")
            return {"error": f"API request failed: {str(e)}"}

    def parse_response(self, text):
        career_advice = {"title": "", "description": "", "roadmap": []}
        recommended_courses = []
        current_section = None
        current_course = None
        
        # Normalize line endings and split
        lines = text.replace('\r\n', '\n').split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Detect sections
            if "**Career Title:**" in line:
                current_section = "title"
                career_advice["title"] = line.split("**Career Title:**", 1)[1].strip()
                continue
                
            elif "📌 **Description:**" in line:
                current_section = "description"
                continue
                
            elif "🗺 **Career Roadmap:**" in line:
                current_section = "roadmap"
                continue
                
            elif "📚 **Recommended Courses:**" in line:
                current_section = "courses"
                continue

            # Parse content based on current section
            if current_section == "description":
                if not career_advice["description"]:
                    career_advice["description"] = line
                else:
                    career_advice["description"] += "\n" + line
                    
            elif current_section == "roadmap":
                if line.startswith("✅ **Step"):
                    step = line.split(":", 1)[1].strip() if ":" in line else line.replace("✅", "").strip()
                    career_advice["roadmap"].append(step)
                    
            elif current_section == "courses":
                # New course
                if line[0].isdigit() and "**Title:**" in line:
                    if current_course:  # Save previous course if exists
                        recommended_courses.append(current_course)
                    title = line.split("**Title:**", 1)[1].strip()
                    current_course = {
                        "title": title,
                        "description": "",
                        "url": "",
                        "platform": ""
                    }
                
                # Course details
                elif current_course:
                    if "**Description:**" in line:
                        current_course["description"] = line.split("**Description:**", 1)[1].strip()
                    elif "**URL:**" in line:
                        url = line.split("**URL:**", 1)[1].strip()
                        # Clean markdown links if present
                        if "[" in url and "](" in url:
                            url = url.split("](", 1)[1].rstrip(")")
                        current_course["url"] = url
                        
                        # Add thumbnail for YouTube
                        if "youtube.com" in url.lower() or "youtu.be" in url.lower():
                            current_course["thumbnail"] = self.get_youtube_thumbnail(url)
                            
                    elif "**Platform:**" in line:
                        current_course["platform"] = line.split("**Platform:**", 1)[1].strip()

        # Add the last course if it exists
        if current_course:
            recommended_courses.append(current_course)

        # Clean up description
        career_advice["description"] = career_advice["description"].strip()
        
        return career_advice, recommended_courses

    def get_youtube_thumbnail(self, video_url):
        try:
            parsed_url = urlparse(video_url)
            if 'youtube.com' in parsed_url.netloc:
                video_id = parse_qs(parsed_url.query).get('v', [''])[0]
            elif 'youtu.be' in parsed_url.netloc:
                video_id = parsed_url.path[1:]
            else:
                return ""
                
            if video_id:
                return f"https://img.youtube.com/vi/{video_id}/hqdefault.jpg"
            return ""
        except Exception:
            return ""


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