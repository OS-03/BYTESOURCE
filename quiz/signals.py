import django.dispatch

from django.db.models.signals import post_save
from django.contrib.auth.models import User
from django.dispatch import receiver

csv_uploaded = django.dispatch.Signal(["user", "csv_file_list"])
