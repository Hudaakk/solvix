# Generated by Django 5.1.4 on 2025-03-21 08:59

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('tcms_app', '0003_remove_testcase_expected_result_and_more'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='teststep',
            options={'ordering': ['step_number']},
        ),
        migrations.RemoveField(
            model_name='teststep',
            name='step_description',
        ),
    ]
