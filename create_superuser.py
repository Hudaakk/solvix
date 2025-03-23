# create_superuser.py
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tcms.settings')
django.setup()

from django.contrib.auth import get_user_model
from tcms_app.models import Role

User = get_user_model()

def create_superuser():
    # Ensure a default role exists
    role, created = Role.objects.get_or_create(role_name='Developer')

    # Create the superuser
    User.objects.create_superuser(
        username='admin',
        email='admin@example.com',
        password='admin@123',
        role=role  # Set the role here
    )

if __name__ == '__main__':
    create_superuser()