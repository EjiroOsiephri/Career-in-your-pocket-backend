from rest_framework import serializers
from django.contrib.auth import get_user_model

from .models import CareerAdviceHistory

User = get_user_model()


class CareerAdviceHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = CareerAdviceHistory
        fields = ["query", "response", "created_at"]

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ["id", "first_name", "last_name", "email", "password"]

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)

        # Update other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        # Update password securely
        if password:
            instance.set_password(password)

        instance.save()
        return instance

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['password'] = "********"  # Optional: placeholder if you want to show "show password" field in frontend
        return data
