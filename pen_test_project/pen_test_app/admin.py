from django.contrib import admin
from .models import Users,ScanStatus,Report

admin.site.register(Users)
admin.site.register(ScanStatus)
admin.site.register(Report)