# Generated by Django 5.0.3 on 2024-03-17 10:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pen_test_app', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ScanStatus',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.URLField(unique=True)),
                ('status', models.CharField(choices=[('scheduled', 'Scheduled'), ('in progress', 'In Progress'), ('completed', 'Completed'), ('error', 'Error')], max_length=20)),
            ],
        ),
    ]