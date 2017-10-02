from rest_framework import routers

from api import views

router = routers.DefaultRouter()
router.register(r'items', views.ItemsViewSet)
