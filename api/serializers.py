from rest_framework import serializers

from models import ObItem


class ItemsSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = ObItem
        fields = ('item_code', 'item_description_english', 'item_description', 'vat_code', 'vat_percent')
