#!/usr/bin/env python
import os
import django

# Set the Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tcms.settings')
django.setup()

from django.contrib.auth import get_user_model
User = get_user_model()

# Define superuser credentials
SUPERUSER_USERNAME = 'admin'
SUPERUSER_EMAIL = 'admin@example.com'
SUPERUSER_PASSWORD = 'admin@123'  # Change this to a secure password

# Create superuser if it doesn't exist
if not User.objects.filter(username=SUPERUSER_USERNAME).exists():
    User.objects.create_superuser(
        username=SUPERUSER_USERNAME,
        email=SUPERUSER_EMAIL,
        password=SUPERUSER_PASSWORD
    )
    print(f"Superuser '{SUPERUSER_USERNAME}' created successfully")
else:
    print(f"Superuser '{SUPERUSER_USERNAME}' already exists")