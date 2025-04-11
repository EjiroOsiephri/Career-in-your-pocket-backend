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
import json

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

            full_prompt = f"""
User Input: {user_input}

Provide detailed career advice for exactly 3 career paths based on the user's input. Use this EXACT format for each career path:

**Career Title:** [Job Title]

📌 **Description:**
[2-3 paragraph description]

🗺 **Career Roadmap:**
1. [Detailed step 1]
2. [Detailed step 2]
3. [Detailed step 3]

📚 **Recommended Courses:**
1. **Title:** [Course 1]
   - **Description:** [Description]
   - **URL:** [Direct URL]
   - **Platform:** [Platform]

2. **Title:** [Course 2]
   - **Description:** [Description]
   - **URL:** [Direct URL]
   - **Platform:** [Platform]

3. **Title:** [Course 3]
   - **Description:** [Description]
   - **URL:** [Direct URL]
   - **Platform:** [Platform]

Important:
- Only include the 3 career paths in this format
- Use plain URLs without markdown
- No additional text before or after
"""
            logger.info(f"Full prompt: {full_prompt}")

            deepseek_response = self.get_deepseek_response(full_prompt)
            if isinstance(deepseek_response, dict) and "error" in deepseek_response:
                return Response(deepseek_response, status=500)

            logger.info(f"Raw DeepSeek response: {deepseek_response}")

            career_advice, recommended_courses = self.parse_response(deepseek_response)

            with transaction.atomic():
                CareerAdviceHistory.objects.create(
                    user=request.user,
                    query=full_prompt,
                    response=deepseek_response
                )

            return Response({
                "career_advice": career_advice,
                "recommended_courses": recommended_courses
            }, status=200)

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
                {"role": "system", "content": "You are a career advisor. Provide concise career guidance in the exact format specified."},
                {"role": "user", "content": user_input}
            ],
            "temperature": 0.7,
            "max_tokens": 2000  # Kept your value
        }

        try:
            session = requests.Session()
            response = session.post(
                "https://api.deepseek.com/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=(10, 60),
                stream=True  # Kept your value
            )
            response.raise_for_status()

            content = []
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    content.append(chunk.decode('utf-8'))
            
            data = json.loads("".join(content))
            return data["choices"][0]["message"]["content"]

            
        except requests.exceptions.Timeout:
          logger.error("DeepSeek API timeout after 60s")
          return {"error": "API request timed out"}
        except Exception as e:
          logger.error(f"DeepSeek API error: {str(e)}")
          return {"error": str(e)}

    def parse_response(self, text):
        career_advice = []
        recommended_courses = []
        lines = text.split('\n')
        i = 0

        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue

            # Career Title
            if line.startswith('**Career Title:**'):
                current_path = {'title': line.split('**Career Title:**')[1].strip(), 'description': '', 'roadmap': []}
                current_courses = []
                i += 1

            # Description
            elif line.startswith('📌 **Description:**') and 'current_path' in locals():
                desc_lines = []
                i += 1
                while i < len(lines) and not lines[i].startswith('🗺 **Career Roadmap:**'):
                    if lines[i].strip():
                        desc_lines.append(lines[i].strip())
                    i += 1
                current_path['description'] = ' '.join(desc_lines)

            # Roadmap
            elif line.startswith('🗺 **Career Roadmap:**') and 'current_path' in locals():
                roadmap_steps = []
                i += 1
                while i < len(lines) and not lines[i].startswith('📚 **Recommended Courses:**'):
                    step_line = lines[i].strip()
                    if step_line and step_line[0].isdigit() and step_line[1] == '.':
                        roadmap_steps.append(step_line.split('.', 1)[1].strip())
                    i += 1
                current_path['roadmap'] = roadmap_steps[:3]  # Limit to 3 steps

            # Courses
            elif line.startswith('📚 **Recommended Courses:**') and 'current_path' in locals():
                i += 1
                current_course = None
                while i < len(lines) and (not lines[i].startswith('**Career Title:**') and lines[i].strip() != '---'):
                    line = lines[i].strip()
                    if not line:
                        i += 1
                        continue
                    if line[0].isdigit() and '**Title:**' in line:
                        if current_course:
                            current_courses.append(current_course)
                        current_course = {
                            'title': line.split('**Title:**')[1].strip(),
                            'description': '',
                            'url': '',
                            'platform': ''
                        }
                    elif current_course and line.startswith('- **Description:**'):
                        current_course['description'] = line.split('**Description:**')[1].strip()
                    elif current_course and line.startswith('- **URL:**'):
                        url = line.split('**URL:**')[1].strip()
                        current_course['url'] = url
                        if 'youtube.com' in url.lower() or 'youtu.be' in url.lower():
                            current_course['thumbnail'] = self.get_youtube_thumbnail(url)
                    elif current_course and line.startswith('- **Platform:**'):
                        current_course['platform'] = line.split('**Platform:**')[1].strip()
                    i += 1
                if current_course:
                    current_courses.append(current_course)
                career_advice.append(current_path)
                recommended_courses.append(current_courses)

            else:
                i += 1

        logger.info(f"Parsed career_advice: {career_advice}")
        logger.info(f"Parsed recommended_courses: {recommended_courses}")
        return career_advice, recommended_courses

    def get_youtube_thumbnail(self, url):
        try:
            video_id = None
            if 'youtube.com/watch' in url:
                video_id = url.split('v=')[1].split('&')[0]
            elif 'youtu.be' in url:
                video_id = url.split('/')[-1].split('?')[0]
            if video_id:
                return f'https://img.youtube.com/vi/{video_id}/hqdefault.jpg'
        except Exception:
            pass
        return ''


class CareerHistoryView(generics.ListAPIView):
    serializer_class = CareerAdviceHistorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return CareerAdviceHistory.objects.filter(user=self.request.user).order_by("-created_at")

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        parsed_data = []
        for item in queryset:
            career_advice, recommended_courses = self.parse_response(item.response)
            parsed_data.append({
                "id": item.id,
                "created_at": item.created_at,
                "query": item.query,
                "career_advice": career_advice,
                "recommended_courses": recommended_courses
            })
        return Response(parsed_data)

    def parse_response(self, text):
        # Reuse the parse_response method from CareerAdviceView
        career_advice = []
        recommended_courses = []
        lines = text.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue
            if line.startswith('**Career Title:**'):
                current_path = {'title': line.split('**Career Title:**')[1].strip(), 'description': '', 'roadmap': []}
                current_courses = []
                i += 1
            elif line.startswith('📌 **Description:**') and 'current_path' in locals():
                desc_lines = []
                i += 1
                while i < len(lines) and not lines[i].startswith('🗺 **Career Roadmap:**'):
                    if lines[i].strip():
                        desc_lines.append(lines[i].strip())
                    i += 1
                current_path['description'] = ' '.join(desc_lines)
            elif line.startswith('🗺 **Career Roadmap:**') and 'current_path' in locals():
                roadmap_steps = []
                i += 1
                while i < len(lines) and not lines[i].startswith('📚 **Recommended Courses:**'):
                    step_line = lines[i].strip()
                    if step_line and step_line[0].isdigit() and step_line[1] == '.':
                        roadmap_steps.append(step_line.split('.', 1)[1].strip())
                    i += 1
                current_path['roadmap'] = roadmap_steps[:3]
            elif line.startswith('📚 **Recommended Courses:**') and 'current_path' in locals():
                i += 1
                current_course = None
                while i < len(lines) and (not lines[i].startswith('**Career Title:**') and lines[i].strip() != '---'):
                    line = lines[i].strip()
                    if not line:
                        i += 1
                        continue
                    if line[0].isdigit() and '**Title:**' in line:
                        if current_course:
                            current_courses.append(current_course)
                        current_course = {
                            'title': line.split('**Title:**')[1].strip(),
                            'description': '',
                            'url': '',
                            'platform': ''
                        }
                    elif current_course and line.startswith('- **Description:**'):
                        current_course['description'] = line.split('**Description:**')[1].strip()
                    elif current_course and line.startswith('- **URL:**'):
                        current_course['url'] = line.split('**URL:**')[1].strip()
                    elif current_course and line.startswith('- **Platform:**'):
                        current_course['platform'] = line.split('**Platform:**')[1].strip()
                    i += 1
                if current_course:
                    current_courses.append(current_course)
                career_advice.append(current_path)
                recommended_courses.append(current_courses)
            else:
                i += 1
        return career_advice, recommended_courses



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

def health_check(request):
    return JsonResponse({"status": "ok"})