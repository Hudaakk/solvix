from django.contrib.auth import get_user_model
from tcms_app.models import Role
import uuid  # Import this if you want to use UUID

User = get_user_model()
try:
    admin_role, created = Role.objects.get_or_create(role_name="Admin")
    
    if not User.objects.filter(username="fathima_huda").exists():
        user = User.objects.create(
            username="fathima_huda",
            email="fathimahudaakk@gmail.com",
            first_name="Fathima",
            last_name="Huda",
            is_staff=True,
            is_superuser=True,
            user_id=str(uuid.uuid4()),  # Generate a unique ID
            # Alternatively, use any other method to generate a unique ID
            # user_id="admin_user_1",
        )
        # Set the role after creation
        user.set_password("huda@123")
        user.role = admin_role
        user.save()
        print("Admin user created successfully")
    else:
        print("Admin user already exists")
except Exception as e:
    print(f"Admin user creation failed: {e}")