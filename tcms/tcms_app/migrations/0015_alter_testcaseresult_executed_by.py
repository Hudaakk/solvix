# Generated by Django 5.1.7 on 2025-03-26 03:46

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tcms_app', '0014_alter_testcaseresult_executed_by'),
    ]

    operations = [
        migrations.AlterField(
            model_name='testcaseresult',
            name='executed_by',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='test_results', to=settings.AUTH_USER_MODEL),
        ),
    ]
