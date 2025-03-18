from rest_framework import serializers

from . import models

class HelloSerializer(serializers.Serializer):
	"""Serializes a name field for testing our APIView"""
	name = serializers.CharField(max_length=10)


class UserProfileSerializer(serializers.ModelSerializer):
	"""Serializer a user profile object"""

	class Meta:
		model = models.UserProfile
		fields = ('id', 'email', 'name', 'password')
		extra_kwargs = {
			'password': {
				'write_only': True,
				'style': {'input_type': 'password'}
			}
		}

		## Overwriding create function. Create method is needed to convert the validated data into a new instance of our model. This model further saves the model instance to the database. A SERIALIZER ENCAPSULATES BOTH VALIDATION AND PERSISTENCE LOGIC
		def create(self, validated_data):
			"""Create and return a new user"""
			user = models.UserProfiles.objects.create_user(
					email = validated_data['email'],
					name = validated_data['name'],
					password = validated_data['password']
				)

			return user

		def update(self, instance, validated_data):
			"""Handle updating user account"""
			if 'password' in validated_data:
				password = validated_data.pop('password')
				instance.set_password(password)
 
			return super().update(instance, validated_data)


