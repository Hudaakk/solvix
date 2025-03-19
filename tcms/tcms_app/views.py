from django.contrib.auth import authenticate, get_user_model
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import LoginSerializer, PasswordResetSerializer, UserSerializer, ChangePasswordSerializer, RoleSerializer, EditSerializer, CreateUserSerializer, AddProfilePictureSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.conf import settings
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.utils.timezone import now
import random, string
from rest_framework.filters import SearchFilter, OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from django.contrib.auth.hashers import make_password
from django.urls import reverse
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.exceptions import AuthenticationFailed
from rest_framework.generics import ListAPIView
from .models import Role
from rest_framework.parsers import MultiPartParser, FormParser







User = get_user_model()

#Login
    
class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        print("request data:", request.data )
        if serializer.is_valid():
            username = serializer.validated_data['username']  # Can be username or email
            password = serializer.validated_data['password']

            # Check if identifier is an email or username
            user = User.objects.filter(email=username).first()  # Try to find a user by email
            if user:
                username = user.username  # Get the username linked to email
            else:
                username = username  # Treat it as a username

            # Authenticate user using username
            user = authenticate(request, username=username, password=password)

            if user is not None:
                if not user.role:
                    return Response({"message": "Access denied! No role assigned."}, status=status.HTTP_403_FORBIDDEN)
                
                if not user.is_active:
                    return Response({"message": "Your account is inactive. Contact admin!"}, status=status.HTTP_403_FORBIDDEN)

            
                # Update last_login and activate user
                user.last_login = now()
                user.save(update_fields=['last_login'])

                # Generate JWT token
                refresh = RefreshToken.for_user(user)

                return Response({
                    'message': f"{user.role.role_name} has logged in successfully!",
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'role': user.role.role_name,
                    'name': f"{user.first_name} {user.last_name}",
                    "email": user.email
                }, status=status.HTTP_200_OK)
            
            return Response({"message": "Invalid credentials!"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#Logout
class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                return Response({"error": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
        
#forgot password
class ForgotPasswordAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Get the email from the request data
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Check if a user with the provided email exists
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Return a success message even if the user doesn't exist (to avoid leaking information)
            return Response({
                "message": "If an account with this email exists, you will receive a password reset email shortly."
            }, status=status.HTTP_200_OK)
        
        # Generate a password reset token and encode the user's primary key
        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

        # Build the password reset URL
        # reset_url = f"{request.build_absolute_uri('/api/reset-password/')}?uid={uidb64}&token={token}"

        frontend_url = "http://192.168.251.86:5173"
        reset_url = f"{frontend_url}/reset-password/{uidb64}/{token}"

        # Prepare the email content
        subject = "Password Reset Request"
        message = (
            f"Hi {user.username},\n\n"
            "We received a request to reset your password. Click the link below to set a new password:\n"
            f"{reset_url}\n\n"
            "If you didn't request this, please ignore this email.\n"
            "Thank you."
        )

        try:
            # Debugging: Print email details
            # print(f"Attempting to send email to {user.email}...")  # Debugging
            # print(f"Reset URL: {reset_url}")  # Debugging
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            print("Email sent successfully!")  # Debugging
        except Exception as e:
            # Log the error and return a 500 response
            print(f"Error sending email: {e}")  # Debugging
            return Response({"error": "Failed to send email."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Return a success response
        return Response({
            "message": "If an account with this email exists, you will receive a password reset email shortly."
        }, status=status.HTTP_200_OK)

    
#reset password
class ResetPasswordAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            uidb64 = serializer.validated_data.get('uid')
            token = serializer.validated_data.get('token')
            new_password = serializer.validated_data.get('new_password')
            
            try:
                # Decode the uidb64 to get the user id
                uid = force_str(urlsafe_base64_decode(uidb64))
                user = User.objects.get(pk=uid)
            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                return Response({"error": "Invalid uid."}, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate the token
            token_generator = PasswordResetTokenGenerator()
            if not token_generator.check_token(user, token):
                return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
            
            # Set the new password and save the user
            user.set_password(new_password)
            user.save()

            return Response({"message": "Password reset successful."}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

#generate random password
def generate_random_password(length = 12):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()-_"
    return "".join(random.choice(characters) for _ in range(length))


#add users
class AddUserView(APIView):
    permission_classes = [IsAuthenticated]  # Only logged-in users can access

    def post(self, request):
        try:
            if not request.user.role or request.user.role.role_name.lower() != "admin":
                return Response({"error": "Permission denied. Only admins can add users."}, status=status.HTTP_403_FORBIDDEN)

            data = request.data.copy()

            print("received data:", data)

            if not data.get("user_id"):
                return Response({"error": "User ID is required."}, status=status.HTTP_400_BAD_REQUEST)
            
            if User.objects.filter(user_id=data.get("user_id")).exists():
                return Response({"error": "User ID already exists."}, status=status.HTTP_400_BAD_REQUEST)

            # Check if user already exists
            if User.objects.filter(email=data.get('email')).exists():
                return Response({"error": "User with this email already exists."}, status=status.HTTP_400_BAD_REQUEST)
            

            try:
                role = Role.objects.get(id=data.get("role"))
            except Role.DoesNotExist:
                return Response({"error": "Invalid role ID."}, status=status.HTTP_400_BAD_REQUEST)


            # Generate a random password for the user
            random_password = generate_random_password()
            data['password'] = random_password  # Password is set here, serializer will hash it

            # Profile picture initially None
            data['profile_picture'] = None

            serializer = CreateUserSerializer(data=data)
            if serializer.is_valid():
                user = serializer.save()

                # Send email with temporary password
                subject = "Welcome to Solvix - Set Your Password"
                message = f"""
                Hi {user.first_name} {user.last_name},

                Your account has been created successfully. Below are your login credentials:

                Temporary Password: {random_password}

                🚨 Security Notice: Please log in immediately and change your password to secure your account.

                Regards,
                Solvix Admin
                """
                try:
                    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
                except Exception as e:
                    return Response({"error": "User created, but email sending failed."}, status=status.HTTP_201_CREATED)

                return Response(
                    {
                        "message": "User created successfully. Password reset email sent.",
                        "user": serializer.data,
                    },
                    status=status.HTTP_201_CREATED,
                )

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#List users     
class UserListView(ListAPIView):
    permission_classes = [IsAuthenticated] 
    queryset = User.objects.all()
    serializer_class = UserSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]

    filterset_fields = ['role', 'status']
    
    search_fields = ['first_name', 'last_name', 'email']
    
    ordering_fields = ['id', 'first_name', 'last_name', 'email', 'role', 'status']

    def get_queryset(self):

        if not self.request.user.role or self.request.user.role.role_name.lower() != "admin":
            return User.objects.none()  # Return empty queryset if not admin

        return User.objects.exclude(role__role_name__iexact="admin")



#Delete user
class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated]  # Only logged-in users can access

    def delete(self, request, user_id):
        try:
            # Check if the logged-in user is an admin
            if not request.user.role or request.user.role.role_name.lower() != "admin":
                return Response({"error": "Permission denied. Only admins can delete users."}, status=status.HTTP_403_FORBIDDEN)

            # Find the user to delete
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

            # Soft delete (Deactivate instead of removing completely)
            user.is_active = False
            user.status = "inactive"
            user.save()

            return Response({"message": "User has been deactivated successfully."}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#Change password
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        serializer = ChangePasswordSerializer(data = request.data, context = {'request' : request})

        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            return Response({"message": "Password changed successfully!"}, status = status.HTTP_200_OK)
        
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)


#Role create
class RoleCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):

        serializer = RoleSerializer(data = request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"role created successfully", "role": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


#Role List
class RoleListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_role = request.user.role.role_name  # Get logged-in user's role

        if user_role.lower() == "admin":
            roles = Role.objects.exclude(role_name="Admin")

        elif user_role.lower() == "project manager":
            roles = Role.objects.exclude(role_name__in=["Admin", "Project Manager"])

        else:
            roles = Role.objects.all()

        serializer = RoleSerializer(roles, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
       

#Edit user
class EditUserView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, user_id):
        if not request.user.role or request.user.role.role_name.lower() != "admin":
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            user = User.objects.get(pk = user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = EditSerializer(user, data= request.data, partial = True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User updated successfully", "user": serializer.data}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

#view user profile
class UserprofileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        try:
            user = User.objects.get(pk = user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status = status.HTTP_404_NOT_FOUND)
        serializer = UserSerializer(user)
        return Response(serializer.data, status = status.HTTP_200_OK)


# view profile
class ProfileView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure user is logged in

    def get(self, request):
        user = request.user  # Automatically gets the logged-in user
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


#Add profile picture
class AddProfilePictureView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        user = request.user
        serializer = AddProfilePictureSerializer(user, data = request.data, partial = True)

        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'profile picture updated successfully', 'data': serializer.data}, status = status.HTTP_200_OK)
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)


from .serializers import  ProjectListSerializer, ModuleSerializer, ProjectSerializer, LeadProjectListSerializer, TaskSerializer, DeveloperSerializer, NotificationSerializer
from rest_framework.generics import CreateAPIView, ListCreateAPIView, RetrieveAPIView
from .models import Project, ProjectTeam, ProjectStatus, Module, Task, Notification, TaskComment, ModuleStatus
from rest_framework.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404


#projectManagerList

class ProjectManagerListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        queryset = User.objects.filter(role__role_name__iexact = "Project Manager")
        logged_in_user = self.request.user

        if logged_in_user.role.role_name.lower() == "project manager":
            queryset = sorted(queryset, key = lambda user: user != logged_in_user)

        return queryset
    
    


#filter UserBy role

class UserListByRoleView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        print("Query Params:", request.query_params)  
        role_id = request.query_params.get("role", "").strip()
        specialization = request.query_params.get("specialization", "").strip()

        print("Role ID After Stripping:", specialization)  

        if not role_id:
            return Response([], status=status.HTTP_200_OK)

        try:
            role_id = int(role_id)
            users = User.objects.filter(role__id=role_id)

            # Exclude users who are currently assigned to active projects
            active_projects = Project.objects.filter(status__in=["in_progress", "Pending"])
            users = users.exclude(id__in = ProjectTeam.objects.filter(project__in = active_projects).values_list("user_id", flat=True))

            # If specialization filter is provided and role is Developer, filter further
            role_name = Role.objects.get(id=role_id).role_name.lower()
            if role_name == "developer" and specialization:
                users = users.filter(specialization=specialization)

            serializer = UserSerializer(users, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except (ValueError, Role.DoesNotExist):
            return Response({"error": "Invalid role ID"}, status=status.HTTP_400_BAD_REQUEST)
        

#create project 

class CreateProjectView(CreateAPIView):

    queryset  = Project.objects.all()
    serializer_class = ProjectSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user

        if not user.role or user.role.role_name.lower() != "project manager":
            raise PermissionDenied("Permission Denied")
        
        project = serializer.save()

        if project.project_lead != user:
            Notification.objects.create(
                user = project.project_lead,
                message = f"You have been assigned as the Project Lead for '{project.project_name}'."
            )

        for team_member in project.project_team.all():
            Notification.objects.create(
                user = team_member.user,
                message = f"You have been added to the project '{project.project_name}'."
            )
    

#projectListView

class ProjectListView(ListAPIView):

    permission_classes = [IsAuthenticated]
    serializer_class = ProjectListSerializer

    def get_queryset(self):
        user = self.request.user

        # Projects where the user is the Project Lead

        project_lead_projects = Project.objects.filter(project_lead=user)

        # Projects where the user is in the Project Team

        project_team_projects = Project.objects.filter(project_team__user=user, project_team__status="active")
        return (project_lead_projects | project_team_projects).distinct().order_by("-created_at")

# project detail view

class ProjectDetailView(RetrieveAPIView):
    queryset = Project.objects.all()
    serializer_class = ProjectListSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = "pk"


#delete Project

class ProjectArchiveAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk, *args, **kwargs):
        try:
            project = Project.objects.get(pk = pk)
            project.status = ProjectStatus.ARCHIVED
            project.save()

            return Response({"message": "Project archived successfully!"}, status=status.HTTP_200_OK)
        except Project.DoesNotExist:
            return Response({"error": "Project not found!"}, status=status.HTTP_404_NOT_FOUND)
        

# restore archived project

class ProjectRestoreAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk, *args, **kwargs):
        try:
            project = Project.objects.get(pk=pk, status=ProjectStatus.ARCHIVED)
            project.status = ProjectStatus.PENDING  # Change status back to pending or any other default
            project.save()

            return Response({"message": "Project restored successfully!"}, status=status.HTTP_200_OK)
        except Project.DoesNotExist:
            return Response({"error": "Project not found or not archived!"}, status=status.HTTP_404_NOT_FOUND)

#lead project list

class LeadProjectListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = LeadProjectListSerializer

    def get_queryset(self):
        user = self.request.user
        return Project.objects.filter(project_lead = user)
    


#create and List module

class ProjectModuleView(ListCreateAPIView):

    permission_classes = [IsAuthenticated]
    serializer_class = ModuleSerializer

    def get_queryset(self):

        project_id = self.kwargs["project_id"]
        return Module.objects.filter(project_id = project_id).order_by("-priority")
    
    def create(self, request, *args, **kwargs):
        user=self.request.user
        
        if not user.role or user.role.role_name.lower() != "project manager":
            raise PermissionDenied("Permission Denied")

        project_id = kwargs['project_id']
        project = get_object_or_404(Project, id = project_id)

        serializer = self.get_serializer(data=request.data, context={"project": project})

        if serializer.is_valid():
            serializer.save(project = project)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


# create and list task
class ModuleTaskView(ListCreateAPIView):

    permission_classes = [IsAuthenticated]
    serializer_class = TaskSerializer

    def get_queryset(self):
        module_id = self.kwargs["module_id"]
        return Task.objects.filter(module_id=module_id).order_by("-priority")

    def create(self, request, *args, **kwargs):
        user=self.request.user
        print("request data", request.data)


        if not user.role or user.role.role_name.lower() != "project manager":
            raise PermissionDenied("Permission Denied")

        module_id = kwargs["module_id"]
        module = get_object_or_404(Module, id=module_id)


        serializer = self.get_serializer(data=request.data, context={"module": module})

        if serializer.is_valid():
            task = serializer.save(module=module, created_by=request.user)

            # Handle comment creation
            comment_content = request.data.get("comment", "").strip()
            if comment_content:
                TaskComment.objects.create(user=request.user, task=task, content=comment_content)

            # Send notification to assigned users
            assigned_users = []

            if isinstance(task.assigned_to, ProjectTeam):
                if task.assigned_to.user:  # Ensure ProjectTeam has a User
                    assigned_users.append(task.assigned_to.user)
            elif isinstance(task.assigned_to, User):  # Direct User assignment
                assigned_users.append(task.assigned_to)

            for user in assigned_users:
                Notification.objects.create(
                    user=user,
                    message=f"You have been assigned a new task: {task.task_name}. Due Date: {task.due_date}"
                )

            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# developers list for task

class ProjectDevelopersView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = DeveloperSerializer

    def get_queryset(self):
        project_id = self.kwargs["project_id"]
        project = get_object_or_404(Project, id=project_id)

        # Filter users in the project team who have the role "Developer"
        developers = ProjectTeam.objects.filter(
            project=project, status="active", user__role__role_name="Developer"
        ).values_list("user", flat=True)

        return User.objects.filter(id__in=developers)
    


# View notification

class NotificationListView(ListAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user = self.request.user).order_by("-created_at")
    

# mark notification as read

class MarkNotificationAsRead(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request, notification_id):

        try:
            notification = Notification.objects.get(id = notification_id, user = request.user)
            notification.status = "read"
            notification.save()
            return Response({"message": "Notification marked as read"}, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({"error": "Notification not found"}, status=status.HTTP_404_NOT_FOUND)
        
    


# task list view in developer dashboard

class DeveloperTaskListView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        if pk:
            # Fetch a single task
            task = get_object_or_404(Task, pk=pk, assigned_to__user=request.user)
            return Response(TaskSerializer(task).data)
        else:
            # Fetch all assigned tasks 
            tasks = Task.objects.filter(assigned_to__user=request.user)
            return Response(TaskSerializer(tasks, many=True).data)


from rest_framework.decorators import api_view, permission_classes

# update task status

@api_view(["PATCH"])
@permission_classes([IsAuthenticated])

def update_task_status(request, pk):

    task = get_object_or_404(Task, pk=pk, assigned_to__user=request.user)
    new_status = request.data.get("status")

    valid_statuses = ["to_do", "in_progress", "completed"]

    if new_status not in valid_statuses:
        return Response({"error": "Invalid status"}, status=status.HTTP_400_BAD_REQUEST)

    task.status = new_status
    task.save()

    return Response({"message": f"Task status updated to {new_status}", "task": TaskSerializer(task).data}, status=status.HTTP_200_OK)



# track task list

class TrakTaskListView(ListAPIView):
    serializer_class =TaskSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
         return Task.objects.filter(
            assigned_to__user=self.request.user).exclude(status="completed").order_by("due_date")
    

    def list(self, request, *args, **kwargs):

        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        task_count = queryset.count()

        return Response({"task_count": task_count, "tasks":serializer.data})


# module list in QA

class ProjectCompletedModuleView(ListAPIView):

    permission_classes = [IsAuthenticated]
    serializer_class = ModuleSerializer

    def get_queryset(self):

        project_id = self.kwargs["project_id"]
        return Module.objects.filter(project_id = project_id, status = ModuleStatus.COMPLETED).order_by("-priority")
    


from .serializers import TestTypeSerializer, TestCaseSerializer, TestEngineersSerializer
from.models import TestType, TestCase, TestComment, UserTestCase, TaskStatus


class TestTypeLisCreateView(ListCreateAPIView):

    permission_classes = [IsAuthenticated]
    serializer_class = TestTypeSerializer
    queryset = TestType.objects.all()



# list test engineers in a project
class TestEngineerView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TestEngineersSerializer

    def get_queryset(self):
        project_id = self.kwargs["project_id"]
        project = get_object_or_404(Project, id=project_id)

        # Filter users in the project team who have the role "Developer"
        testEngineers = ProjectTeam.objects.filter(
            project=project, status="active", user__role__role_name="Test Engineer"
        ).values_list("user", flat=True)

        return User.objects.filter(id__in=testEngineers)
    

# Test create and list

class ModuleTestCaseView(ListCreateAPIView):

    permission_classes = [IsAuthenticated]
    serializer_class = TestCaseSerializer

    def get_queryset(self):

        module_id = self.kwargs["module_id"]
        return TestCase.objects.filter(module_id = module_id).order_by("-priority")
    
    def create(self, request, *args, **kwargs):

        user = self.request.user

        if not user.role or user.role.role_name.lower() != "qa":
            return Response({"error": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        
        module_id = kwargs["module_id"]
        module = get_object_or_404(Module, id = module_id)

        serializer = self.get_serializer(data = request.data, context = {"module": module})

        if serializer.is_valid():
            test_case = serializer.save(module = module, created_by = request.user)

            # get assigned users from request data

            assigned_user_ids = request.data.get("assigned_users", [])
             
            #assign test case to project team members

            for user_id in assigned_user_ids:
                project_team_member = ProjectTeam.objects.filter(user_id = user_id, project = module.project)
                for project_team_member in project_team_member:
                    UserTestCase.objects.create(test_case=test_case, assigned_to=project_team_member)
           

            # comment creation

            comment_content = request.data.get("comment", "").strip()
            if comment_content:
                TestComment.objects.create(user = request.user, test = test_case, content = comment_content)

            # notify assigned users
            for user_id in assigned_user_ids:
                user = get_object_or_404(User, id=user_id)
                Notification.objects.create(
                    user = user,
                    message = f"A new test case '{test_case.test_title}' has been created in module '{module.module_name}'." 
                )

            return Response(serializer.data, status = status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)
    


# developer dashboard task statistics

@api_view(["GET"])
@permission_classes([IsAuthenticated])

def developer_task_statistics(request):

    assigned_tasks = Task.objects.filter(assigned_to__user = request.user)

    
    total_tasks = assigned_tasks.count()
    completed_tasks = assigned_tasks.filter(status = TaskStatus.COMPLETED).count()
    pending_tasks = total_tasks - completed_tasks


    return Response({
        "total_tasks": total_tasks,
        "completed_tasks": completed_tasks,
        "pending_tasks": pending_tasks
    }, status=status.HTTP_200_OK)


# developer fetch recent tasks

@api_view(["GET"])
@permission_classes([IsAuthenticated])

def developer_recent_tasks(request):

    recent_tasks = (
        Task.objects.filter(assigned_to__user = request.user).order_by("-updated_at")[:5]
    )

    task_data = [
        {
            "task_id": task.task_id,
            "task_name": task.task_name,
            "status": task.status,
            "priority": task.priority,
            "updated_at": task.updated_at,
        }
        for task in recent_tasks
    ]

    return Response({"recent_tasks": task_data}, status=status.HTTP_200_OK)


