#!/bin/bash
# Exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Create superuser script
cat > create_superuser.py << 'EOL'
#!/usr/bin/env python
import os
import sys
import django

# Add the current directory to the Python path
sys.path.append(os.getcwd())

# Set the Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tcms.settings')
django.setup()

from django.contrib.auth import get_user_model
User = get_user_model()

# Define superuser credentials
SUPERUSER_USERNAME = 'admin'
SUPERUSER_EMAIL = 'admin@example.com'
SUPERUSER_PASSWORD = 'Admin123!'  # Change this to a secure password

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
EOL

# Navigate to the directory containing manage.py
cd tcms

# Apply migrations
python manage.py collectstatic --no-input
python manage.py makemigrations
python manage.py migrate

# Create superuser (run the script from within the tcms directory)
python ../create_superuser.py