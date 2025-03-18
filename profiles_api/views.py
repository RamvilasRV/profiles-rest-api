from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, viewsets
from rest_framework.authentication import TokenAuthentication

from . import serializers, models, permissions

class HelloApiView(APIView):
	""" Test API View """

	serializer_class = serializers.HelloSerializer

	def get(self, request, format=None):
		"""Returns a list of APIView features"""
		an_apiview = [
			'uses HTTP methods as function (get, post, patch, put, delete)',
			'Is similar to a traditional django view',
			'Gives you the most control over your applicatio logic',
			'Is mapped manually to URLs',
		]
		return Response({'message':'Hello', 'an_apiview':an_apiview})


	def post(self, request):
		"""Create a hell messge with our name"""
		serializer = self.serializer_class(data=request.data)
		print(serializer)

		if serializer.is_valid():
			name = serializer.validated_data.get('name')
			message = f"Hey there {name}"
			return Response({"message":message})
		else:
			return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


	def put(self, request, pk=None):
		"""Handle updating an object"""
		return Response({"method":'PUT'})

	def patch(self, request, pk=None):
		"""Handle partial update an object"""
		return Response({"method":'PATCH'})

	def delete(self, request, pk=None):
		"""Delete an object"""
		return Response({"method":'DELETE'})



class HelloViewSet(viewsets.ViewSet):
	"""Test API ViewSet"""

	serializer_class = serializers.HelloSerializer

	def list(self, request):
		"""Return a hello message"""
		a_viewset = ["Uses actions (list, create, retrieve, update, partial_update)",
		'Automatically maps to URLs using Routers', 
		'Provides more functionality with less code']
		return Response({"message":"Hello", "a_viewset":a_viewset})

	def create(self, request):
		"""Create a new hello message"""
		serializer = self.serializer_class(data=request.data)

		if serializer.is_valid():
			name = serializer.validated_data.get('name')
			message = f"Hello {name}!!!!"
			return Response({"message":message})
		else:
			return Response(
				serializer.errors, 
				status = status.HTTP_400_BAD_REQUEST
				)

	def retrieve(self, request, pk=None):
		"""handle getting an object by it ID"""
		return Response({"http_method":'GET'})

	def update(self, request, pk=None):
		"""handle updating an object by it ID"""
		return Response({"http_method":'UPDATE'})

	def partial_update(self, request, pk=None):
		"""handle partially updating an object by it ID"""
		return Response({"http_method":'PARTIAL UPDATE'})

	def destroy(self, request, pk=None):	
		"""handle deleting an object by it ID"""
		return Response({"http_method":'DELETE'})




class UserProfileViewSet(viewsets.ModelViewSet):
	"""handles creating and updating profiles"""
	serializer_class = serializers.UserProfileSerializer
	queryset = models.UserProfile.objects.all()
	authetication_classes = (TokenAuthentication, )
	permission_classes = (permissions.UpdateOwnProfile, )