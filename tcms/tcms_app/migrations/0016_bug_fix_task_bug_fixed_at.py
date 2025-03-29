# Generated by Django 5.1.7 on 2025-03-29 03:59

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tcms_app', '0015_alter_testcaseresult_executed_by'),
    ]

    operations = [
        migrations.AddField(
            model_name='bug',
            name='fix_task',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='bug_fixes', to='tcms_app.task'),
        ),
        migrations.AddField(
            model_name='bug',
            name='fixed_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
