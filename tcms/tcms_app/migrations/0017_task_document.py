# Generated by Django 5.1.7 on 2025-03-29 07:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tcms_app', '0016_bug_fix_task_bug_fixed_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='task',
            name='document',
            field=models.FileField(blank=True, null=True, upload_to='task_documents/'),
        ),
    ]
