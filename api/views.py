# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from rest_framework import viewsets

from models import ObItem
from serializers import ItemsSerializer


# Create your views here.

def home(request):
    item_list = ObItem.objects.all()
    context = {'item_list': item_list}
    return render(request, 'api/index.html', context)


class ItemsViewSet(viewsets.ModelViewSet):
    """
    API endpoint that gives items list.
    """
    queryset = ObItem.objects.all()
    serializer_class = ItemsSerializer
