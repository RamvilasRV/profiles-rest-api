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