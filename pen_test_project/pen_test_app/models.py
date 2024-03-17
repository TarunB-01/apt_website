from django.db import models

class Users(models.Model):
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)

    def __str__(self):
        return self.username


class ScanStatus(models.Model):
    url = models.URLField(max_length=100)
    status = models.CharField(max_length=20, choices=[
        ('scheduled', 'Scheduled'),
        ('in progress', 'In Progress'),
        ('completed', 'Completed'),
        ('error', 'Error')
    ])
    timestamp = models.DateTimeField(auto_now_add=True)  # Add timestamp field with auto_now_add=True

    def __str__(self):
        return self.url

class Report(models.Model):
    scan_status = models.ForeignKey(ScanStatus, on_delete=models.CASCADE)
    report_file = models.FileField(upload_to='reports/')