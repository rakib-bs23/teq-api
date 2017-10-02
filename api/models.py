# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


# Create your models here.
class ObItem(models.Model):
    is_discard = models.NullBooleanField()
    credit_account_no = models.CharField(max_length=1000, blank=True, null=True)
    create_date = models.DateTimeField(blank=True, null=True)
    # create_uid = models.ForeignKey('ResUsers', models.DO_NOTHING, db_column='create_uid', blank=True, null=True)
    item_code = models.CharField(unique=True, max_length=60)
    item_description_english = models.TextField()
    write_date = models.DateTimeField(blank=True, null=True)
    vat_code = models.CharField(max_length=1000, blank=True, null=True)
    vat_percent = models.FloatField(blank=True, null=True)
    # write_uid = models.ForeignKey('ResUsers', models.DO_NOTHING, db_column='write_uid', blank=True, null=True)
    item_description = models.TextField()

    class Meta:
        managed = True
        db_table = 'ob_item'

    def __str__(self):
        return self.item_description_english
