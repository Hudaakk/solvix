# Generated by Django 5.1.7 on 2025-04-07 05:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tcms_app', '0024_module_is_deleted'),
    ]

    operations = [
        migrations.AlterField(
            model_name='testcase',
            name='status',
            field=models.CharField(choices=[('assigned', 'Assigned'), ('failed', 'Failed'), ('completed', 'Completed'), ('reassigned', 'Reassigned')], default='assigned', max_length=20),
        ),
    ]
