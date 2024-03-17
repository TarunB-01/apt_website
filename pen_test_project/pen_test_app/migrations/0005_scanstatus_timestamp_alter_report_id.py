# Generated by Django 5.0.3 on 2024-03-17 14:35

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pen_test_app', '0004_report'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanstatus',
            name='timestamp',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='report',
            name='id',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
    ]
