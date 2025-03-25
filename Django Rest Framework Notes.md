**Title** : Django rest framework
**Date** : 11/03/2025

**Source**: [Udemy](https://www.udemy.com/course/django-python/)
**Tags** : #restapi #drf

*The course will teach us to create an API that handles creating an updating user profiles, login and authentication, posting and listing content*

____
## Creation of project
```shell
django-admin startproject profiles_project .
```

## Creation of app.
```shell
python manage.py startapp profiles_api
```

Enable this app by adding the app into the  settings.py file


>[!info]
>While creating an API using django, we need to mention the below apps in the settings.py along with our custom apps.
>- rest_framework
>- rest_framework.authtoken

____


## Setting up the Database.

### Creating the User model.
Django comes with it's own model for user authentication, but here we are overriding the inbuilt model. We are overriding the default username field with the email field *(When we use the Django's inbuilt model out of the box, when authenticating, it asks for the username and password, and not the user email. So, we are changing it to ask for email address instead of the name)*. 

```python
#models.py

from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from django.contirb.auth.models import PermissionsMixin


class UserProfile(AbstractBaseUser, PermissionsMixin):
	""" Database model for the users in the system """
	email = models.EmailField(max_length=255, unique=True)
	name = models.CharField(max_length=255)
	is_active = models.BooleanField(default=True)
	is_staff = models.BooleanField(default=False)

	objects = UserProfileManager()

	USERNAME_FIELD = 'email'
	REQUIRED_FIELDS = ['name']

	def get_full_name(self):
		""" Retrive full name of the user """
		return self.name

	def short_name(self):
		""" Retrive short name """
		return self.name

	def __str__(self):
		""" Return string representation of our user """
		return self.email
```


>[!question]
>We have created a profile manager called UserProfileManager. But what exactly is a manager? and why do we use it? 
>
>*This is created so that django knows how to work with model in the django command line tools*


### Creating a Model Manager.
Since we have customized the user model, we need to let django know how to interact with this model. For example, if we run the `createsuperuser` command, django does not know that we have customized the user model and hence will not work properly. We need to tell django how to interact with this user model because, by default, , when it creates a user, it expects a username and a password and not an email.

The way a manager works is that, we can define functions within in the manager, that can be used to manipulate the objects in the model that the manager is for.

```python
class UserProfileManager(BaseUserManager):
	""" Manager for user profiles """

	def create_user(self, email, name, password=None):
		"""Create a new user profile"""
		if not email:
			raise ValueError("Users must have an email adress")

		email = self.normalize_email(email)
		user = self.model(email=email, name=name)

		user.set_password(password)
		user.save(using=self._db)

		return user

	def create_superuser(self, email, name, password):
		"""Create and save a superuser with the given details"""
		user = self.create_user(email, name, password)

		user.is_superuser = True
		user.is_staff = True
		user.save(using=self.db)

		return user
```

>[!warning]
>The function names in the manager, `create_user` and `create_superuser` are not arbitrary names given. They are expected by django and should not be changed.
>


### Configuring the project to use the customized user model as the default user model.

We need to mention the default user model in the settings.py

```python
AUTH_USER_MODEL = 'profiles_api.UserProfile'
```

Add the above line in the settings.py file. The syntax is 
```python
AUTH_USER_MODEL = '<app_name>.<model_name>'
```

___

## Setting up the Django Admin.

### Creating super user.
Use the below command to create a superuser
```shell
python manage.py createsuperuser
```


### Enable django admin for the user profile model.
Go to the apps `admin.py` file and import the models into them.

```python
#admin.py
from django.contrib import admin

from profiles_api import models

admin.site.register(models.UserProfiles)
```


___


## API Views
Django provides us with helper classes that can be used to create our API endpoints.
- APIView
- ViewSet

 APIView is the most basic type of view that can be used to build our API.

### What are APIViews?
- It enables us to describe the logic that makes our endpoint.
- Allows us to define functions that match the standard HTTP methods.
- Give us the most control over the logic
- Perfect for implementing complex logic like working with logic files or calling other API

### When should we use APIViews?
- It depends on personal preference.
- When we need full control over our application logic, such as updating multiple data sources in a single call
- When calling other external APIs
- When you need to access local files or data.


### Create a API view.

```python
#views.py

from rest_framework.views import APIView
from rest_framework.response import Response

class HelloApiView(APIView):
	""" Test API View """

	def get(self, request, format=None):
		"""Returns a list of APIView features"""
		an_apiview = [
			'uses HTTP methods as function (get, post, patch, put, delete)',
			'Is similar to a traditional django view',
			'Gives you the most control over your applicatio logic',
			'Is mapped manually to URLs',
		]
		return Response({'message':'Hello', 'an_apiview':an_apiview})
```


### Creating a Serializer.
- A feature from DRF to convert data inputs in to python object and vice-versa.
- Serializer also helps in validating the data sent by the user during a POST request.

It's a good idea to keep all the serializers in a separate file in the app.

Here, we are making a serializer to validate if the `name` data passed by the user is under 10 characters or not. 

```python
# serializers.py

from rest_framework import serializers

class HelloSerializer(serializers.Serializer):
	"""Serializes a name field for testing our APIView"""
	name = serializers.CharField(max_length=10)
```


```python
#views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from . import serializers

class HelloApiView(APIView):
	""" Test API View """

	serializer_class = serializers.HelloSerializer

	def post(self, request):
		"""Create a hello messge with our name"""
		serializer = self.serializer_class(data=request.data)
		print(serializer)

		if serializer.is_valid():
			name = serializer.validated_data.get('name')
			message = f"Hey there {name}"
			return Response({"message":message})
		else:
			return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

```

### ModelSerialier
ModelSerializer is a layer of abstraction over the default serializer that allows to quickly create a serializer for a model in Django.


___

## ViewSet
- Allow us to write logic, just like APIViews
- Instead of defining functions which map to HTTP methods, ViewSets accept functions that map to common API object actions such as 
	- list
	- create
	- retrieve
	- update
	- partial_update
	- destroy
- Perfect for standard database operations
- Fastest way to make an API that interfaces with database backend

### When do we use ViewSet?
- When you API is a simple CRUD interface.
- A quick way to manage predefined objects.
- Little to no customization on the logic is needed.
- If the API is working with standard data structure.


### Creating a simple viewset (with serializers).

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, viewsets

from . import serializers

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
```

#### Routers
In general, to run a view, we associate the view to a URL using the `urls.py` file. But, in the case of a ViewSet, things are a little bit different. 
We use routers to generate the URLs. Routers automatically generate URL patterns for the standard actions based on the viewset, reducing boilerplate code.

```python
#urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
# router.register(name_of_the_url_that_we_wish_to_create, viewset_that_we_wish_to_register)
router.register('hello-viewset', views.HelloViewSet, basename="hello-viewset")

urlpatterns = [
	path("hello-view/", views.HelloApiView.as_view()),
	path("", include(router.urls))
]
```


>[!note]
>In this part of the example, it might seem as thought there is no need of using ViewSets, but note that in the APIViews, we will not be able to dynamically change the primary key. Hence it's not dynamic at all. If we had to make it dynamic, ,we would have to add more URLs like `root/{id}/patch`


___

## Building the actual API

### The Plan
Our API is going to be able to handle the following:
- Create New Profiles
	- Handle registration of new users
	- Validate profile data
- Listing existing profiles
	- Search for profiles
	- Email and name
- View specific profiles
	- Profile ID
-  Update profile of logged in user
	- Change name, email and password
- Delete Profile.


### API URLs
- Profiles - api/profile/
	- Lists all the profiles when HTTP GET method is called
	- Create new profile when HTTP POST method is called.
	- If an ID is provided, we can view all the details of the profile using HTTP GET.
	- Update the user object using HTTP PUT or PATCH
	- Remove it completely using HTTP DELETE.


### The build.

#### Create Profiles
##### Model serializer
Starting with creating a **model serializer** for the profiles model.

```python
# serializer.py
from rest_framework import serializers

from . import models

class UserProfileSerailizer(serializers.ModelSerializer):
	"""Serializer a user profile object"""

	class Meta:
		model = model.UserProfile
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
```

- In this serializer, we are using the meta function to tell the serializer which database to point to.
- We are passing the fields values in the meta function to tell it which fields should be serialized and which should not be. Since our model many other fields like is_active and is_staff, which should not be handled by the API user, we are exposing only few fields in the serializer.
- When the serializer validates the data and if the data is valid, it calls the `save()` function which in turn calls the `create()` function. By overriding create(), you delegate user creation to the manager’s create_user() method, ensuring consistency with how the model expects users to be created.
- Update() function is used when the models needs to be updated to store the password by hashing it and in plain text format

>[!info]
>A SERIALIZER ENCAPSULATES BOTH VALIDATION AND PERSISTENCE LOGIC

After the serializer, we are creating a **ModelViewSet**
```python
# views.py
def UserProfileViewSet(viewsets.ModelViewSet):
	"""handles creating and updating profiles"""
	serializer_class = serializers.UserProfileSerializer
	queryset = models.UserProfiles.objects.all()
```

##### urls.py
Once this is done, we need to create a **URL** for this.

```python
# urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views
router = DefaultRouter()
router.register('profile', views.UserProfileViewSet)

urlpatterns = [
	path("", include(router.urls))
]
```

>[!warning]
>I don't know how routers work or how to use them. Also, without the UI, what endpoint would i hit to achieve PUT and PATCH?

##### Creating permission class
Creating the **Permission Class**. 
The problem with this API is that anyone can edit anyone's profile details. Which is not a right thing.
- We can add permissions on these requests. What happens it that, every time a request is made, the permission function will be called and given the request object, the view and the object that we are checking the permissions against. 

```python
from rest_framework import permissions

class UpdateOwnProfile(permissions.BasePermission):
	"""Allow users to edit their own profile"""

		def has_object_permission(self, request, view, obj):
			""" Check user is trying to edit their own profile"""
			if request.method in permissions.SAFE_METHODS:
				return True
			return obj.id == request.user.id
```

- In the above code, we are letting the users access the endpoint only if the request method belongs to the `SAFE_METHODS`. Safe methods are those methods that do not make any changes to the object (PUT, PATCH, DELETE).
- If the request type is not in the safe methods, we check if the user id is equal to the id in the object and allowing it only they match. Essentially, letting people edit the object that belongs to their profile. 

#### Add search profiles feature.
Making the objects searchable is straightforward. We just add the `filter_backends` and `search_fields` parameters in the views.

```python
# views.py
from rest_framework import status, viewsets, filters

class UserProfileViewSet(viewsets.ModelViewSet):
	"""handles creating and updating profiles"""
	serializer_class = serializers.UserProfileSerializer
	queryset = models.UserProfile.objects.all()
	authetication_classes = (TokenAuthentication, )
	permission_classes = (permissions.UpdateOwnProfile, )
	filter_backends = (filters.SearchFilter, )
	search_fields = ('name', 'email', )
```

This is create a new option on the page to search the objects based on the search parameter given. All it does is adds a new search parameter on the URL as shown below.
```URL
http://localhost:8000/api/profile/?search=tes
```


#### Login Functionality (Using token authentication)

Token authentication - A token is generated when a user is logged in and every request needs to carry the token in our header so that we can authenticate. For this, we need to create an endpoint to generate a token. Django comes with inbuilt `AuthTokenView` that makes it easy to add a login API.

```python
## views.py
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_Settings

def UserLoginApiView(ObtainAuthToken):
	"""Handle creating user authentication tokens"""
	renderer_classes = api_Settings.DEFAULT_RENDERER_CLASSES
```

Adding the URL
```python
## urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

 
urlpatterns = [
	path('login/', views.UserLoginApiView.as_view()),
]
```

Running this will generate a token and in future, we will see how to use it and add them to the headers.

The way that the token authentication works is that the the token is added to the authentication head of the request.

>[!info]
>Since we had not generated the token, but given the token as a authentication way for us to be able to edit our profile.. We were not able to edit it on the URL `/api/profile/<id>`. But now, once we add the token to our header using modheader, we can now access our profile and edit it..

___


### Planning the feed API
Our feed API needs to be able to handle the below functionalities.
- Create new feed items
- Updating an existing feed.
- Deleting an item
- View other users feed.

Our API will have the below URLs.
- /api/feed -> List all feed items
	- GET (list feed items)
	- POST (create feed item for logged in user)
- /api/feed/<feed_item_id> -> Manage specific feed items
	- GET (Get the feed item)
	- PUT/PATCH (update feed item)
		- DELETE (delete feed item)


### Adding a new model item
The first step to create such a feed API would be to create a model to store the users feed items.

```python
#models.py
class ProfileFeedItem(models.Model):
	"""profile status update"""
	user_profile = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete = models.CASCADE
	)
	status_text = models.CharField(max_length=255)
	created_on = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		"""Return the model as a string"""
		return self.status_text
```

Once the models is completed, **migrate** it and then **register the model to the admin**.


### Creating a serializer for profile feed items.

```python
#serialzer.py

class ProfileFeedItemSerialzer(serializers.ModelSerializer):
	"""Serializer for the profile feed items"""

	class Meta:
		model = models.ProfileFeedItem
		fields = ('id', 'user_profile', 'status_text', 'created_on')
		extra_kwargs = {
			'user_profile': {"read_only": True}
		}
```

In this serializer, `id` and `created_on` are already read-only, since the fields are generated by django. We are making the `user_profile` field as a read-only, because otherwise, a user will be able to create a post and set to some other user.


### Creating a viewset for the feeds.
```python
# views.py
class UserProfileFeedViewSet(viewsets.ModelViewSet):
	"""hanles creating, reading, and updating profile feed items"""
	authentication_classes = (TokenAuthentication, )
	serializer_class = serializers.ProfileFeedItemSerializer
	queryset = models.ProfileFeedItem.objects.all()

	def perform_create(self, serializer):
		"""Sets the user profile to the logged in user"""
		serializer.save(user_profile=self.request.user)
```

```python
# urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
router = DefaultRouter()
# router.register(name_of_the_url_that_we_wish_to_create, viewset_that_we_wish_to_register)
router.register('hello-viewset', views.HelloViewSet, basename="hello-viewset")
router.register('profile', views.UserProfileViewSet)
router.register('feed', views.UserProfileFeedViewSet) ## added this line..
 
urlpatterns = [
	path("hello-view/", views.HelloApiView.as_view()),
	path('login/', views.UserLoginApiView.as_view()),
	path("", include(router.urls))
]
```

There is a `perform_create` function in the `views.py`. The reason for that is, our database has 4 columns. Out of which, 2 columns (`id` and `created-at`) is filled automatically. The `status_text` is filled by the user. But the user cant fill in the `user_profile` field. That is because that field is a read-only field. But since that field is a necessary field, we are overriding the save method that actually runs in the background.
When the data is passed by the user, it is further passed to the serializer and it takes care of saving the data to the database as well. Serializer than validated the data and then runs the `save` method to save the data to the database. Now, the data passed to the serializer contains of the `id`, `status_text` and the `created_at` fields, but it does not have the `user_profile` data. Hence, we need to customize that method so as to add the `user_profile` according to the one that we want (Currently authenticated user, in this case). So, we create a new function named `perform_create` to override the default save method and add the currently authenticated user in the database.



### Adding permissions to the feed API.
According to our code, we are able to attempt to create a post, even if we are not logged in (Although we don't really create any thing and end up with an error page because we are not allowed to add `None` in the `user_profile` in the models.), which we should not be able to do.
Also, a user should only be able to edit only their posts and not anyone else's. To avoid all these things, we will be adding permissions to our API.

```python
# permissions.py

class UpdateOwnStatus(permissions.BasePermission):
	"""Allow user to update thier ownn status"""

	def has_object_permission(self, request, view, obj):
		"""Check if the user is trying to update their own status"""
		if request.method in permissions.SAFE_METHODS:
			return True
		return obj.user_profile.id == request.user.id
```

```python
# views.py
from rest_framework.permissions import IsAuthenticatedOrReadOnly

class UserProfileFeedViewSet(viewsets.ModelViewSet):
	"""hanles creating, reading, and updating profile feed items"""
	authentication_classes = (TokenAuthentication, )
	serializer_class = serializers.ProfileFeedItemSerializer
	queryset = models.ProfileFeedItem.objects.all()
	permission_classes = (
		permissions.UpdateOwnStatus,
		IsAuthenticatedOrReadOnly
	) ## This is added new..

	def perform_create(self, serializer):
		"""Sets the user profile to the logged in user"""
		serializer.save(user_profile=self.request.user)
```

Along with the permission class that we created, we have also included a `IsAuthenticatedOrReadOnly` permission. It is inbuilt in django and does not let the user edit anything if they are not authenticated.


### Restricting viewing status updates to logged in users only.
If you don't want the users to even read the status if they are not logged in, you can use `IsAuthenticated` instead of `IsAuthenticatedOrReadOnly`.







