from django.apps import AppConfig
from django.contrib.auth import get_user_model
from django.db.utils import IntegrityError
from django.db.models.signals import post_migrate


def create_admin_user(sender, **kwargs):
    User = get_user_model()

    try:

        from tcms_app.models import Role

        admin_role, created = Role.objects.get_or_create(role_name = "Admin")

        if not User.objects.filter(username = "admin").exists():
            user = User(
                username = "fathima_huda",
                email = "fathimahudaakk@gmail.com",
                first_name = "Fathima",
                last_name = "Huda",
                role = admin_role,
                is_staff = True,
                is_superuser = True
            )
            user.set_password("huda@123")
            user.save()
            print("Admin user created successfully")

    except IntegrityError:
        print("Admin user creation failed")
    except Exception as e:
        print(f"An error occured: {e}")




class TcmsAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'tcms_app'

    def ready(self):
        post_migrate.connect(create_admin_user, sender = self)
