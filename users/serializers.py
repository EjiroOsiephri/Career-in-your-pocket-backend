from rest_framework import serializers
from django.contrib.auth import get_user_model

from .models import CareerAdviceHistory

User = get_user_model()


class CareerAdviceHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = CareerAdviceHistory
        fields = ["query", "response", "created_at"]

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

    class Meta:
        model = User
        fields = ["id", "first_name", "last_name", "email", "password"]
