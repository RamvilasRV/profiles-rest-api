from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from . import serializers

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
