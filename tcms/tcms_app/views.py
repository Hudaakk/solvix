from django.contrib.auth import authenticate, get_user_model
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import LoginSerializer, PasswordResetSerializer, UserSerializer, ChangePasswordSerializer, RoleSerializer, EditSerializer, CreateUserSerializer, AddProfilePictureSerializer, ProjectDetailSerializer
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
    
       

#Edit user profile by admin
class EditUserView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, user_id):
        print("request:", request.data)
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
    


    
from rest_framework.decorators import api_view, permission_classes

#Remove profile pics
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def remove_profile_picture(request):
    user = request.user  # Get logged-in user
    
    if user.profile_picture:  
        user.profile_picture.delete(save=False)  # Delete the file from storage
        user.profile_picture = None
        user.save()
        return Response({"message": "Profile picture removed successfully."}, status=status.HTTP_200_OK)
    
    return Response({"error": "No profile picture to remove."}, status=status.HTTP_400_BAD_REQUEST)


from .serializers import UserUpdateSerializer

# edit profile

class UserUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        serializer = UserUpdateSerializer(user, data=request.data, partial = True)

        if serializer.is_valid():
            serializer.save()
            return Response({"message":"Profile updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


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

            # # Exclude users who are currently assigned to active projects
            # active_projects = Project.objects.filter(status__in=["in_progress", "Pending"])
            # users = users.exclude(id__in = ProjectTeam.objects.filter(project__in = active_projects).values_list("user_id", flat=True))

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
    

from rest_framework.generics import UpdateAPIView
#Edit project

class UpdateProjectView(UpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProjectSerializer
    queryset = Project.objects.all()

    def get_object(self):

        project_id = self.kwargs.get("project_id")
        print(f"Received project_id: {project_id}")  # Debugging log

        return get_object_or_404(Project, id = project_id)
    
    def perform_update(self, serializer):
        print("Requested data:", self.request.data)

        user = self.request.user
        # Only allow project managers to update the project.
        if not user.role or user.role.role_name.lower() != "project manager":
            raise PermissionDenied("Permission Denied")
        # Save the updated project.
        project = serializer.save()

        # Optionally, update notifications if team members change or if the project is updated.
        # Here we notify all team members that the project has been updated.
        for team_member in project.project_team.all():
            Notification.objects.create(
                user=team_member.user,
                message=f"The project '{project.project_name}' has been updated."
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
    serializer_class = ProjectDetailSerializer
    lookup_field = "pk"


#delete Project

class ProjectArchiveAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk, *args, **kwargs):
        try:
            project = Project.objects.get(pk=pk)
            project.status = ProjectStatus.ARCHIVED
            project.save(update_fields=['status'])
            project.refresh_from_db()  # Ensure changes reflect in the response

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
            module = serializer.save(project=project)
            # If the project is still pending, update its status to in_progress
            if project.status == ProjectStatus.PENDING:
                project.status = ProjectStatus.IN_PROGRESS
                project.save(update_fields=['status'])
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



from .models import TaskType

# create and list task
class ModuleTaskView(ListCreateAPIView):

    permission_classes = [IsAuthenticated]
    serializer_class = TaskSerializer

    def get_queryset(self):
        module_id = self.kwargs["module_id"]
        return Task.objects.filter(module_id=module_id).order_by("-priority")

    def create(self, request, *args, **kwargs):
        user = self.request.user
        print("request data", request.data)

        # Check permission - Only Project Managers can create tasks
        if not user.role or user.role.role_name.lower() != "project manager":
            raise PermissionDenied("Permission Denied")

        module_id = kwargs["module_id"]
        module = get_object_or_404(Module, id=module_id)

        # Extract user_id from request data
        user_id = request.data.get("assigned_to")  # Expecting user_id

        # Validate if user_id exists in ProjectTeam for the same project
        project_team = ProjectTeam.objects.filter(user_id=user_id, project=module.project, status="active").first()

        if not project_team:
            return Response({"error": "User is not part of the project team"}, status=status.HTTP_400_BAD_REQUEST)

        # Add ProjectTeam ID instead of User ID
        request.data["assigned_to"] = project_team.id  # Assigning ProjectTeam ID

        document = request.FILES.get("document", None)
        task_type = TaskType.MODULE

        serializer = self.get_serializer(data=request.data, context={"module": module})

        if serializer.is_valid():
            task = serializer.save(module=module, created_by=request.user, document=document, task_type = task_type)

            # Handle comment creation
            comment_content = request.data.get("comment", "").strip()
            if comment_content:
                TaskComment.objects.create(user=request.user, task=task, content=comment_content)

            # Send notification to assigned user
            assigned_user = project_team.user  # Get the user from ProjectTeam
            Notification.objects.create(
                user=assigned_user,
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
        return ProjectTeam.objects.filter(
        project=project, status="active", user__role__role_name="Developer")
        
    


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


#list the completed list of task 
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def completed_developer_tasks(request):
    # Get the current logged-in developer
    developer = request.user
    
    # Get all project teams where the user is a member
    developer_teams = ProjectTeam.objects.filter(user=developer)
    
    # Get completed tasks assigned to these teams
    completed_tasks = Task.objects.filter(
        assigned_to__in=developer_teams,
        status='completed'
    ).select_related(
        'module__project',
        'assigned_to__user'
    )
    
    serializer = TaskSerializer(completed_tasks, many=True)
    return Response(serializer.data)

#list the pending task 
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def pending_developer_tasks(request):
    developer = request.user
    
    # Get developer's active project team assignments
    developer_teams = ProjectTeam.objects.filter(
        user=developer,
        status='active'
    )
    
    # Filter pending tasks (all non-completed statuses)
    pending_tasks = Task.objects.filter(
        assigned_to__in=developer_teams
    ).exclude(
        status=TaskStatus.COMPLETED
    ).select_related(
        'module__project',
        'assigned_to__user'
    ).order_by('due_date')
    
    serializer = TaskSerializer(pending_tasks, many=True)
    return Response(serializer.data)

# task list view in developer dashboard

class DeveloperTaskListView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        if pk:
            # Fetch a single task
            task = get_object_or_404(Task, pk=pk, assigned_to__user=request.user)
            if task.task_type == TaskType.BUG_FIX:
                serializer = BugTaskSerializer(task)
            else:
                serializer = TaskSerializer(task)
            return Response(serializer.data)
        
        else:
            # Fetch all assigned tasks 
            tasks = Task.objects.filter(assigned_to__user=request.user).order_by('-created_at')
            return Response(TaskSerializer(tasks, many=True).data)


from rest_framework.decorators import api_view, permission_classes

# update task status

@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def update_task_status(request, pk):
    task = get_object_or_404(Task, pk=pk, assigned_to__user=request.user)
    new_status = request.data.get("status")
    valid_statuses = [choice[0] for choice in TaskStatus.choices]
    
    if new_status not in valid_statuses:
        return Response({"error": "Invalid status"}, status=status.HTTP_400_BAD_REQUEST)

    # Update task status and save (progress updated via model's save())
    task.status = new_status
    task.save()  # Now updates both status and progress

    # Update module status via its save() method
    if task.module:
        task.module.save()  # Uses Module's save() logic

    # Handle bug-fix tasks
    if task.task_type == TaskType.BUG_FIX:
        bug = task.bug_fixes.first()  # Get the first linked bug
        if bug:
            resolution_notes = request.data.get("resolution_notes", "")

            if new_status == TaskStatus.IN_PROGRESS:
                bug.fix_status = "in_progress"
                bug.status = "in_progress"
            elif new_status == TaskStatus.COMPLETED:
                bug.fix_status = "fixed"
                bug.status = "resolved"
                bug.fixed_at = timezone.now()
                bug.resolution_notes = resolution_notes

            bug.save(update_fields=["fix_status", "status", "fixed_at", "resolution_notes"])

            # Update TestCase status if bugs are fixed
            test_case_result = getattr(bug, "test_case_result", None)
            if test_case_result:
                test_case = test_case_result.test_case
                related_bugs = test_case_result.bugs.all()

                if any(b.fix_status == "fixed" for b in related_bugs):
                    if test_case.status != TestCaseStatus.ASSIGNED:
                        test_case.status = TestCaseStatus.ASSIGNED
                        test_case.save(update_fields=["status"])

                    # Reset UserTestCases for retesting
                    user_test_cases = test_case.assigned_users.all()
                    for utc in user_test_cases:
                        utc.status = UserTestCaseStatus.TODO
                        utc.save(update_fields=["status"])

                        Notification.objects.create(
                            user=utc.assigned_to.user,
                            message=f"The test case '{test_case.test_title}' has been reassigned to you for retesting."
                        )

                    # Reset failed test steps
                    failed_steps = UserTestStepResult.objects.filter(
                        user_test_case__test_case=test_case,
                        status="fail"
                    )
                    for step_result in failed_steps:
                        step_result.status = "not_run"
                        step_result.save(update_fields=["status"])

    return Response({
        "message": f"Task status updated to {new_status}",
        "task": TaskSerializer(task).data
    }, status=status.HTTP_200_OK)


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
    


# project list in QA
class QAProjectListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = LeadProjectListSerializer

    def get_queryset(self):
        user = self.request.user
        return Project.objects.filter(project_team__user=user, project_team__status="active").distinct()


# module list in QA

class ProjectCompletedModuleView(ListAPIView):

    permission_classes = [IsAuthenticated]
    serializer_class = ModuleSerializer

    def get_queryset(self):

        project_id = self.kwargs["project_id"]
        return Module.objects.filter(project_id = project_id, status = ModuleStatus.COMPLETED).order_by("-priority")
    


from .serializers import TestTypeSerializer, TestCaseSerializer, TestEngineersSerializer, AssignedTestCaseSerializer, UserTestCaseSerializer
from.models import TestType, TestCase, TestComment, UserTestCase, TaskStatus, UserTestCaseStatus, TestStep, UserTestStepResult
from datetime import date


# test type list and create

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
        return ProjectTeam.objects.filter(
        project=project, status="active", user__role__role_name="Test Engineer")
        
    

# Test create and list

class ModuleTestCaseView(ListCreateAPIView):

    permission_classes = [IsAuthenticated]
    serializer_class = TestCaseSerializer

    def get_queryset(self):
        module_id = self.kwargs["module_id"]
        return TestCase.objects.filter(module_id=module_id).order_by("-priority")
    

    def create(self, request, *args, **kwargs):
        user = self.request.user

        if not user.role or user.role.role_name.lower() != "qa":
            raise PermissionDenied("Permission Denied")

        module_id = kwargs['module_id']
        module = get_object_or_404(Module, id = module_id)

        serializer = self.get_serializer(data=request.data, context={"module": module}) 
        print("request data:", request.data)

        if serializer.is_valid():
            testcase = serializer.save(module=module, created_by=request.user)

            assigned_user_ids = request.data.get("assigned_users", []) 
            user_test_cases = []
            for user_id in assigned_user_ids:
                project_team_member = ProjectTeam.objects.filter(user_id=user_id, project=module.project).first()

                if project_team_member:
                    user_test_case = UserTestCase.objects.create(test_case=testcase, assigned_to=project_team_member)
                    user_test_cases.append(user_test_case)

            # Handle Test Steps (Create Test Steps if provided)
            test_steps = []  # Store created test steps
            test_steps_data = request.data.get("test_steps", [])
            for step in test_steps_data:
                test_step = TestStep.objects.create(
                    test_case=testcase,
                    step_number=step["step_number"],
                    step_description=step["step_description"],
                    expected_result=step["expected_result"]
                )
                test_steps.append(test_step)

            # create user test step result
            for user_test_case in user_test_cases:
                for test_step in test_steps:
                    UserTestStepResult.objects.create(
                        user_test_case=user_test_case,
                        test_step=test_step,
                        status="not_run"  # Default status
                    )

            # Comment creation

            comment_content = request.data.get("comment", "").strip()
            if comment_content:
                TestComment.objects.create(user=request.user, test=testcase, content=comment_content)

            # Notify assigned users
            for user_id in assigned_user_ids:
                user = get_object_or_404(User, id=user_id)
                Notification.objects.create(
                    user=user,
                    message=f"A new test case '{testcase.test_title}' has been created in module '{module.module_name}'."
                )

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



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
            "id": task.id,
            "task_id": task.task_id,
            "task_name": task.task_name,
            "status": task.status,
            "priority": task.priority,
            "updated_at": task.updated_at,
        }
        for task in recent_tasks
    ]

    return Response({"recent_tasks": task_data}, status=status.HTTP_200_OK)


# developer dashboard calendar

@api_view(["GET"])
@permission_classes([IsAuthenticated])

def upcoming_deadlines(request):

    today = now().date()

    upcoming_Tasks = Task.objects.filter(
        assigned_to__user = request.user, due_date__gte = today
    ).order_by("due_date").exclude(status="completed").select_related("assigned_to", "module", "module__project").order_by("due_date")


    serializer = TaskSerializer(upcoming_Tasks, many = True).data

    return Response({"upcoming_deadlines": serializer}, status=200)



# test engineer test list

class AssignedTestCaseListView(ListAPIView):

    permission_classes = [IsAuthenticated]
    serializer_class = AssignedTestCaseSerializer

    def get_queryset(self):

        user = self.request.user
        project_team = ProjectTeam.objects.filter(user = user, status = "active").first()

        if not project_team:
            return UserTestCase.objects.none()
        
        return UserTestCase.objects.filter(assigned_to = project_team)
    

# Track test case 

class TrackAssignedTestCaseListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = AssignedTestCaseSerializer

    def get_queryset(self):
        user = self.request.user
        project_team = ProjectTeam.objects.filter(user=user, status="active").first()

        if not project_team:
            return UserTestCase.objects.none()

        return UserTestCase.objects.filter(assigned_to=project_team).exclude(status=UserTestCaseStatus.COMPLETED)
    

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        total_test_cases = queryset.count()
        high_priority_cases = queryset.filter(test_case__priority="high").count()

        response_data = {
            "total_test_cases": total_test_cases,
            "assigned_test_cases": self.serializer_class(queryset, many=True).data
        }
        return Response(response_data, status=status.HTTP_200_OK)


# test case summary in tE dashboard


class TestCaseSummaryView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        project_team = ProjectTeam.objects.filter(user = user, status = "active").first()

        if not project_team:
            return Response({"message": "No active project assigned"}, status=status.HTTP_400)
        
        total_test_cases = UserTestCase.objects.filter(assigned_to = project_team).count()
        completed_test_cases = UserTestCase.objects.filter(
            assigned_to = project_team, status = UserTestCaseStatus.COMPLETED
        ).count()
        
        pending_test_cases = total_test_cases - completed_test_cases

        return Response({
            "total_test_cases" : total_test_cases,
            "completed_test_cases": completed_test_cases,
            "pending_test_cases": pending_test_cases
        })
    

# TE recent activity

class RecentTestEngineerActivities(ListAPIView):

    serializer_class = UserTestCaseSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return UserTestCase.objects.filter(assigned_to__user=user).order_by("-updated_at")[:10]
    

# TE upcoming events

class TestEngineerUpcomingDueView(ListAPIView):


    serializer_class = AssignedTestCaseSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        today = date.today()

        return UserTestCase.objects.filter(
            assigned_to__user = user,
            test_case__due_date__gte = today
        ).order_by("test_case__due_date")
    


# detailed test case view
class TestCaseDetailView(RetrieveAPIView):

    permission_classes = [IsAuthenticated]
    serializer_class = TestCaseSerializer

    def get_queryset(self):
        return TestCase.objects.all()
    
    def get_object(self):
        test_case_id = self.kwargs.get("pk") 
        return get_object_or_404(TestCase, id = test_case_id)
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request  # Pass request into context
        return context
    

    
from rest_framework.generics import RetrieveUpdateAPIView


# edit test case
class TestUpdateView(RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TestCaseSerializer
    lookup_field = "pk"

    def get_queryset(self):
        return TestCase.objects.all()
    
    def update(self, request, *args, **kwargs):
        user = request.user
        # Only allow QA role to edit test cases
        if not user.role or user.role.role_name.lower() != "qa":
            return Response({"error": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        

        test_case = self.get_object()
        serializer = self.get_serializer(test_case, data=request.data, partial=True)

        if serializer.is_valid():
            updated_test_case = serializer.save()

            # Update Assigned Users (if provided)
            assigned_user_ids = request.data.get("assigned_users", None)
            if assigned_user_ids is not None:

                # Remove old assignments and add new ones
                UserTestCase.objects.filter(test_case=updated_test_case).delete()
                for user_id in assigned_user_ids:
                    project_team_member = ProjectTeam.objects.filter(user_id=user_id, project=updated_test_case.module.project).first()
                    if project_team_member:
                        UserTestCase.objects.create(test_case=updated_test_case, assigned_to=project_team_member)
                    else:
                        return Response(
                            {"error": f"User with ID {user_id} is not part of the project team."},
                            status=status.HTTP_400_BAD_REQUEST
                        )

            # Update Test Steps (if provided)
            test_steps_data = request.data.get("test_steps", None)
            if test_steps_data is not None:
                # Remove old steps and add new steps
                TestStep.objects.filter(test_case=updated_test_case).delete()
                for step in test_steps_data:
                    # It's assumed that each step dictionary includes "step_number", "step_description", and "expected_result"
                    TestStep.objects.create(
                        test_case=updated_test_case,
                        step_number=step["step_number"],
                        step_description=step["step_description"],
                        expected_result=step["expected_result"]
                    )

            # Optionally, update Test Comments if a new comment is provided
            comment_content = request.data.get("comment", "").strip()
            if comment_content:
                TestComment.objects.create(user=user, test=updated_test_case, content=comment_content)

            return Response(self.get_serializer(updated_test_case).data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



from .serializers import UserTestStepResultSerializer, BugSerializer
from .models import Bug, Attachment, TestCaseResult


# test case step status update

class UpdateTestStepStatus(APIView):
    def patch(self, request, step_id):
        try:
            test_step = UserTestStepResult.objects.get(id=step_id)
            print("test step:", test_step)
        except UserTestStepResult.DoesNotExist:
            return Response({"error": "Test step not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserTestStepResultSerializer(test_step, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

from django.utils import timezone
from .models import TestCaseStatus
 

#mark complete or report bug by test engineer

class CompleteTestCaseResultView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, user_test_case_id):
        user_test_case = get_object_or_404(UserTestCase, id=user_test_case_id)

        # Ensure all test steps are executed.
        user_steps = user_test_case.user_test_step_results.all()
        if user_steps.filter(status="not_run").exists():
            return Response(
                {"error": "Not all test steps have been executed."},
                status=status.HTTP_400_BAD_REQUEST
            )

        overall_result = "passed" if all(step.status == "pass" for step in user_steps) else "failed"
        remarks = request.data.get("remarks", "")

        # Create the TestCaseResult record using request.user for executed_by.
        test_case_result = TestCaseResult.objects.create(
            test_case=user_test_case.test_case,
            executed_by=request.user,  
            result=overall_result,
            remarks=remarks,
            execution_date=timezone.now()
        )

        bug = None

        # Always use "attachment" from the request.
        attachment_file = request.FILES.get("attachment")
        print("Attachment file: ", attachment_file)

        if overall_result == "passed":
            if attachment_file:
                Attachment.objects.create(
                    file=attachment_file,
                    test_case_result=test_case_result
                )
        else:
            # For failed test cases, process bug details.
            bug_data = request.data.get("bug")
            if not bug_data:
                return Response(
                    {"error": "Bug details are required for a failed test case."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Parse bug data if it's a JSON string.
            if isinstance(bug_data, str):
                import json
                try:
                    bug_data = json.loads(bug_data)
                except Exception as e:
                    return Response(
                        {"error": "Invalid bug data format."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # Determine bug_id.
            if bug_data.get("bug_id"):
                bug_id = bug_data.get("bug_id")
                if Bug.objects.filter(bug_id=bug_id).exists():
                    return Response(
                        {"error": f"Bug id '{bug_id}' already exists."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                bug_id = f"BUG{test_case_result.id}"

            bug_title = bug_data.get("title")
            bug_description = bug_data.get("description")
            bug_priority = bug_data.get("priority", "Medium")
            bug_severity = bug_data.get("severity", "minor")

            # New fields from bug data:
            steps_to_reproduce = bug_data.get("steps_to_reproduce")
            environment = bug_data.get("environment")

            if not bug_title or not bug_description:
                return Response(
                    {"error": "Bug title and description are required."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            bug = Bug.objects.create(
                bug_id=bug_id,
                test_case_result=test_case_result,
                reported_by=request.user,
                title=bug_title,
                description=bug_description,
                priority=bug_priority,
                severity=bug_severity,
                steps_to_reproduce=steps_to_reproduce,  # New field saved
                environment=environment,                # New field saved
                created_at=timezone.now()
            )

            project = user_test_case.test_case.module.project
            pm = project.project_lead  # Assuming project_lead is the PM
            if pm:
                Notification.objects.create(
                    user=pm,
                    message=f"A new bug '{bug.title}' has been reported for test case '{user_test_case.test_case.test_title}' in project '{project.project_name}'."
                )

            if attachment_file:
                # Rewind file pointer before using it for the bug attachment.
                attachment_file.seek(0)
                Attachment.objects.create(
                    file=attachment_file,
                    test_case_result=test_case_result,
                    bug=bug
                )

        # Mark the UserTestCase as COMPLETED.
        user_test_case.status = UserTestCaseStatus.COMPLETED
        user_test_case.save()

        # Update the TestCase status based on progress.
        test_case = user_test_case.test_case
        test_case.get_progress()  # This will update the status
        

        # Prepare the response data.
        data = {
            "test_case_result": {
                "id": test_case_result.id,
                "result": test_case_result.result,
                "remarks": test_case_result.remarks,
                "execution_date": test_case_result.execution_date,
            },
            "bug": None
        }
        if overall_result == "failed" and bug:
            data["bug"] = {
                "id": bug.id,
                "bug_id": bug.bug_id,
                "title": bug.title,
                "description": bug.description,
                "priority": bug.priority,
                "severity": bug.severity,
                "steps_to_reproduce": bug.steps_to_reproduce,
                "environment": bug.environment,
                "status": bug.status,
                "created_at": bug.created_at,
            }

        return Response(data, status=status.HTTP_201_CREATED)

    


# qa list failed testcase

class FailedTestCaseByModuleView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TestCaseSerializer

    def get_queryset(self):

        module_id = self.kwargs.get("module_id")
        module = get_object_or_404(Module, id = module_id)
        return TestCase.objects.filter(module = module, status = TestCaseStatus.FAILED)
    

# list the passed test case
class PassedTestCaseByModuleView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TestCaseSerializer

    def get_queryset(self):

        module_id = self.kwargs.get("module_id")
        module = get_object_or_404(Module, id=module_id)
        return TestCase.objects.filter(module= module, status=TestCaseStatus.COMPLETED)
    


# qa list bugs in a test case

class BugsByTestCaseView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = BugSerializer

    def get_queryset(self):

        test_case_id = self.kwargs.get("test_case_id")
        test_case = get_object_or_404(TestCase, id = test_case_id)
        return Bug.objects.filter(test_case_result__test_case = test_case)
    

# qa bug detail view

class BugDetailView(RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = BugSerializer

    def get_queryset(self):
        return Bug.objects.all()



import json


#report bug by QA
class ReportBugOnTestCaseView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, test_case_id):
        user = request.user

        if not user.role or user.role.role_name.lower() != "qa":
            return Response({"error": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        
        test_case = get_object_or_404(TestCase, id = test_case_id)
        print('request data',request.data)

        #create a TestCaseResult with
        remarks = request.data.get("remarks", "")
        test_case_result = TestCaseResult.objects.create(
            test_case = test_case,
            executed_by = request.user,
            result = "failed",
            remarks = remarks,
            execution_date = timezone.now()
        )

        # Extract bug details from the request.
        bug_data = request.data.get("bug")
        if not bug_data:
            return Response({"error":"Bug details are required."}, status=status.HTTP_400_BAD_REQUEST)
        

        #parse bug dataif its a Json string.
        if isinstance(bug_data, str):
            try:
                bug_data = json.loads(bug_data)
            except Exception as e:
                return Response({"error":"Invalid bug data format."}, status=status.HTTP_400_BAD_REQUEST)
            
        # Determine a unique bug_id.
        if bug_data.get("bug_id"):
            bug_id = bug_data.get("bug_id")
            if Bug.objects.filter(bug_id=bug_id).exists():
                return Response({"error": f"Bug id '{bug_id}' already exists."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            bug_id = f"BUG{test_case_result.id}"

        # Extract required fields.
        bug_title = bug_data.get("title")
        bug_description = bug_data.get("description")
        bug_priority = bug_data.get("priority", "Medium")
        bug_severity = bug_data.get("severity", "minor")
        steps_to_reproduce = bug_data.get("steps_to_reproduce")
        environment = bug_data.get("environment")

        if not bug_title or not bug_description:
            return Response({"error": "Bug title and description are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Create the Bug record linked to the TestCaseResult.
        bug = Bug.objects.create(
            bug_id=bug_id,
            test_case_result=test_case_result,
            reported_by=request.user,
            title=bug_title,
            description=bug_description,
            priority=bug_priority,
            severity=bug_severity,
            steps_to_reproduce=steps_to_reproduce,
            environment=environment,
            created_at=timezone.now()
        )

        # Notify the Project Manager about the new bug.
        project = test_case.module.project  # Access the project from the test case's module.
        pm = project.project_lead           # Assuming the project_lead is the PM.
        if pm:
            Notification.objects.create(
                user=pm,
                message=f"A new bug '{bug.title}' has been reported for test case '{test_case.test_title}' in project '{project.project_name}'."
            )


        # Process an optional attachment file.
        attachment_file = request.FILES.get("attachment")
        if attachment_file:
            attachment_file.seek(0)
            Attachment.objects.create(
                file=attachment_file,
                test_case_result=test_case_result,
                bug=bug
            )

        # Prepare the response data.
        data = {
            "test_case_result": {
                "id": test_case_result.id,
                "result": test_case_result.result,
                "remarks": test_case_result.remarks,
                "execution_date": test_case_result.execution_date,
            },
            "bug": {
                "id": bug.id,
                "bug_id": bug.bug_id,
                "title": bug.title,
                "description": bug.description,
                "priority": bug.priority,
                "severity": bug.severity,
                "steps_to_reproduce": bug.steps_to_reproduce,
                "environment": bug.environment,
                "status": bug.status,
                "created_at": bug.created_at,
            }
        }
        return Response(data, status=status.HTTP_201_CREATED)



# list developer in a module QA

class ModuleDeveloperView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = DeveloperSerializer

    def get_queryset(self):

        module_id = self.kwargs.get("module_id")
        module = get_object_or_404(Module, id = module_id)
        return ProjectTeam.objects.filter(project=module.project, user__role__role_name__iexact="developer")


# qa dashboard test status
class QATestCaseStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        # Filter test cases created by the current QA user.
        qs = TestCase.objects.filter(created_by=request.user)
        total = qs.count()
        assigned = qs.filter(status=TestCaseStatus.ASSIGNED).count()
        completed = qs.filter(status=TestCaseStatus.COMPLETED).count()
        failed = qs.filter(status=TestCaseStatus.FAILED).count()

        data = {
            "total": total,
            "assigned": assigned,
            "completed": completed,
            "failed": failed,
        }
        return Response(data)
    

# QA dashboard recent activities

class RecentTestCaseActivityView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TestCaseSerializer

    def get_queryset(self):
        return TestCase.objects.filter(created_by=self.request.user).order_by('-updated_at')
    

#QA dashboard upcoming events
class UpcomingTestCaseDeadlinesView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TestCaseSerializer

    def get_queryset(self):
        today = timezone.now().date()
        # Filter test cases created by the current user with due dates in the future (or today)
        return TestCase.objects.filter(created_by=self.request.user, due_date__gte=today).order_by('due_date')
    

# Admin dashboard project status

class AdminProjectStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        total_projects = Project.objects.count()
        pending_projects = Project.objects.filter(status=ProjectStatus.PENDING).count()
        in_progress_projects = Project.objects.filter(status=ProjectStatus.IN_PROGRESS).count()
        completed_projects = Project.objects.filter(status=ProjectStatus.COMPLETED).count()
        archived_projects = Project.objects.filter(status=ProjectStatus.ARCHIVED).count()

        data = {
            "total_projects": total_projects,
            "pending_projects": pending_projects,
            "in_progress_projects": in_progress_projects,
            "completed_projects": completed_projects,
            "archived_projects": archived_projects,
        }
        return Response(data)


from .serializers import ProjectBasicSerializer, UserWithProjectsSerializer, TaskCommentSerializer, TestCommentSerializer
from django.db.models import Q


#admin dashboard project management
class RecentProjectsView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProjectListSerializer

    def get_queryset(self):
        # Order by created_at descending so that the first project is the most recently added.
        return Project.objects.all().order_by('-created_at')
    

    
# active and inactive users
class UserStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        users = User.objects.all()
        serialized_users = UserSerializer(users, many=True)

        active_users = User.objects.filter(status="active")
        serialized_active_users = UserSerializer(active_users, many=True)

        inactive_users = User.objects.filter(status="inactive")
        
        return Response({
            'users': serialized_users.data,
            'active_users': serialized_active_users.data,
            'total_users': users.count(),
            'active_count': active_users.count(),
            'inactive_count': inactive_users.count(),
        })
    

#admin dashboard
class UsersWithProjectsListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserWithProjectsSerializer

    def get_queryset(self):
        # Filter users that are either the creator, project lead, or part of a project team.
        return User.objects.filter(
            Q(created_projects__isnull=False) |
            Q(lead_projects__isnull=False) |
            Q(user_project_team__isnull=False)
        ).distinct()
    


#Add task comments

class TaskCommentCreateView(CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TaskCommentSerializer

    def perform_create(self, serializer):
        # Automatically set the user from the request.
        serializer.save(user=self.request.user)



#add test comments

class TestCommentCreateView(CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TestCommentSerializer

    def perform_create(self, serializer):
        # Automatically set the user from the request.
        serializer.save(user=self.request.user)


  


#project details(aggregated information)

class ProjectSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, project_id):

        project = get_object_or_404(Project, id=project_id)

        total_modules = project.modules.count()
        total_tasks = Task.objects.filter(module__project = project).count()
        total_test_cases = TestCase.objects.filter(module__project = project).count()
        total_bugs = Bug.objects.filter(test_case_result__test_case__module__project = project).count()
        progress = project.progress

        data = {
            "project_id": project.id,
            "project_name":project.project_name,
            "total_modules":total_modules,
            "total_tasks":total_tasks,
            "total_test_cases":total_test_cases,
            "total_bugs":total_bugs,
            "progress":progress
        }
        return Response(data, status=status.HTTP_200_OK)


import datetime

#admin dashboard project view details
class AdminProjectDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, project_id):
        project = get_object_or_404(Project, id=project_id)

        team_members = project.project_team.all()
        team_data = []
        for members in team_members:
            full_name = (members.user.first_name + " " + members.user.last_name).strip()
            if not full_name:
                full_name = members.user.username
            team_data.append({
                "full_name":full_name,
                "role":members.user.role.role_name
            })


        #Module details
        modules = project.modules.all()
        module_data = []
        for mod in modules:
            module_data.append({
                "Module_id": mod.Module_id,
                "module_name": mod.module_name,
                "module_description": mod.module_description,
                "due_date": mod.due_date,
                "priority": mod.priority,
                "status": mod.status,
                "progress": mod.progress  # using the property defined in Module
            })

        # get tasks associated with this project

        tasks_qs = Task.objects.filter(module__project = project)
        total_tasks = tasks_qs.count()
        completed_tasks = tasks_qs.filter(status = TaskStatus.COMPLETED).count()
        pending_tasks = total_tasks - completed_tasks


        # Get bugs associated with this project.
        
        bugs_qs = Bug.objects.filter(test_case_result__test_case__module__project=project)
        total_bugs = bugs_qs.count()
        critical_bugs = bugs_qs.filter(severity="critical").count()
        major_bugs = bugs_qs.filter(severity = "major").count()
        minor_bugs = bugs_qs.filter(severity="minor").count()
        trivial_bugs = bugs_qs.filter(severity = "trivial").count()


        # overall progress
        overall_progress = project.progress

        #weekly progress graph

        weekly_data = []
        now = timezone.now()

        number_of_weeks = 4

        for i in range(number_of_weeks, 0, -1):
            week_end = now - datetime.timedelta(days=(i-1)*7)
            week_start = now - datetime.timedelta(days=i*7)
    
            # Tasks progress for the week
            tasks_week = tasks_qs.filter(created_at__gte=week_start, created_at__lt=week_end)
            tasks_created = tasks_week.count()
            tasks_completed = tasks_week.filter(status=TaskStatus.COMPLETED).count()
            tasks_pending = tasks_created - tasks_completed
            if tasks_created > 0:
                tasks_progress = (tasks_completed / tasks_created) * 100
            else:
                tasks_progress = 0

    
            # Modules progress for the week
            modules_week = project.modules.filter(created_at__gte=week_start, created_at__lt=week_end)
            modules_created = modules_week.count()
            modules_completed = modules_week.filter(status=ModuleStatus.COMPLETED).count()
            modules_pending = modules_created - modules_completed
            if modules_created > 0:
                modules_progress = (modules_completed / modules_created) * 100
            else:
                modules_progress = 0
    
            # Test cases progress for the week
            tests_week = TestCase.objects.filter(module__project=project, created_at__gte=week_start, created_at__lt=week_end)
            tests_created = tests_week.count()
            tests_completed_or_failed = tests_week.filter(status__in=[TestCaseStatus.COMPLETED, TestCaseStatus.FAILED]).count()
            tests_pending = tests_created - tests_completed_or_failed
            if tests_created > 0:
                tests_progress = (tests_completed_or_failed / tests_created) * 100
            else:
                tests_progress = 0


            # Combine the progress (simple average)
            overall_week_progress = round((tasks_progress + modules_progress + tests_progress) / 3, 2)

            weekly_data.append({
                "week": f"Week {number_of_weeks + 1 - i}",
                "progress": overall_week_progress,
                "tasks_created": tasks_created,
                "tasks_completed": tasks_completed,
                "tasks_pending": tasks_pending,
                "modules_created": modules_created,
                "modules_completed": modules_completed,
                "modules_pending": modules_pending,
                "tests_created": tests_created,
                "tests_completed_or_failed": tests_completed_or_failed,
                "tests_pending": tests_pending,
            })

        # Prepare the detailed response data.
        data = {
            "project_id": project.project_id,
            "project_name": project.project_name,
            "project_description": project.project_description,
            "project_lead": project.project_lead.get_full_name() if project.project_lead and (project.project_lead.first_name or project.project_lead.last_name) else project.project_lead.username if project.project_lead else None,
            "overall_progress": overall_progress,
            "team": team_data,
            "modules": module_data,
            "task_summary": {
                "total_tasks": total_tasks,
                "completed_tasks": completed_tasks,
                "pending_tasks": pending_tasks,
            },
            "bug_summary": {
                "faults_identified": total_bugs,
                "critical_bugs": critical_bugs,
                "minor_bugs": minor_bugs,
                "major_bugs": major_bugs,
                "trivial_bugs": trivial_bugs
            },
            "weekly_progress": weekly_data
        }
        return Response(data, status=status.HTTP_200_OK)
    


#admin dashboard user details

class AdminReportUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        # Retrieve the target user for whom we want the dashboard metrics.
        target_user = get_object_or_404(User, id=user_id)
        role = target_user.role.role_name.lower()
        data = {}

        if role == "developer":
            projects_assigned = ProjectTeam.objects.filter(user=target_user, status="active")
            total_projects = projects_assigned.count()

            tasks_qs = Task.objects.filter(assigned_to__user=target_user)
            total_tasks = tasks_qs.count()
            completed_tasks = tasks_qs.filter(status=TaskStatus.COMPLETED).count()
            pending_tasks = total_tasks - completed_tasks
            efficiency = (completed_tasks / total_tasks) * 100 if total_tasks > 0 else 0

            data = {
                "role": "developer",
                "total_projects": total_projects,
                "total_tasks": total_tasks,
                "completed_tasks": completed_tasks,
                "pending_tasks": pending_tasks,
                "efficiency": round(efficiency, 2),
            }
        elif role == "qa":
            
            total_created_tests = TestCase.objects.filter(created_by=target_user).count()
            # Count test cases that have been assigned (i.e. have corresponding UserTestCase records)
            total_assigned = UserTestCase.objects.filter(test_case__created_by=target_user).count()
            # Among those, count how many are completed.
            completed_tests = UserTestCase.objects.filter(test_case__created_by=target_user, status=UserTestCaseStatus.COMPLETED).count()
            pending_tests = total_assigned - completed_tests

            # Optionally, count bugs reported for test cases created by this QA.
            bugs_reported = Bug.objects.filter(test_case_result__test_case__created_by=target_user).count()

            # Define efficiency for a QA as the percentage of their test cases that reached a final outcome (completed or failed).
            # We assume that if a test case is not assigned or not executed, it's not efficient.
            finished_tests = UserTestCase.objects.filter(test_case__created_by=target_user, status__in=[UserTestCaseStatus.COMPLETED]).count()
            efficiency = (finished_tests / total_created_tests) * 100 if total_created_tests > 0 else 0

            data = {
                "role": "qa",
                "total_test_cases_created": total_created_tests,
                "total_test_cases_assigned": total_assigned,
                "completed_test_cases": completed_tests,
                "pending_test_cases": pending_tests,
                "bugs_reported": bugs_reported,
                "efficiency": round(efficiency, 2),
            }

        elif role in ["test engineer"]:
            user_test_cases = UserTestCase.objects.filter(assigned_to__user=target_user)
            total_tests = user_test_cases.count()
            completed_tests = user_test_cases.filter(status=UserTestCaseStatus.COMPLETED).count()
            pending_tests = total_tests - completed_tests

            failed_tests = 0
            for utc in user_test_cases:
                result = utc.test_result  # The property returns the latest TestCaseResult.
                if result and result.result == "failed":
                    failed_tests += 1
            efficiency = (completed_tests / total_tests) * 100 if total_tests > 0 else 0

            data = {
                "role": "test engineer",
                "total_tests": total_tests,
                "completed_tests": completed_tests,
                "pending_tests": pending_tests,
                "failed_tests": failed_tests,
                "efficiency": round(efficiency, 2),
            }

        elif role == "project manager":
            # For project managers, count projects, modules, and tasks they created.
            projects_created = Project.objects.filter(created_by=target_user)
            total_projects = projects_created.count()
            modules_created = Module.objects.filter(project__created_by=target_user).count()
            tasks_created = Task.objects.filter(created_by=target_user)
            total_tasks = tasks_created.count()
            completed_tasks = tasks_created.filter(status=TaskStatus.COMPLETED).count()
            pending_tasks = total_tasks - completed_tasks
            efficiency = (completed_tasks / total_tasks) * 100 if total_tasks > 0 else 0

            data = {
                "role": "project manager",
                "total_projects": total_projects,
                "modules_created": modules_created,
                "total_tasks": total_tasks,
                "completed_tasks": completed_tasks,
                "pending_tasks": pending_tasks,
                "efficiency": round(efficiency, 2),
            }

        else:
            data = {"error": "Role not supported for dashboard metrics."}

        return Response(data, status=status.HTTP_200_OK)
    


#admin user detailed view

class AdminuserDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        target_user = get_object_or_404(User, id=user_id)
        role = target_user.role.role_name.lower()

        user_details = {
            "full_name": target_user.get_full_name() or target_user.username,
            "email": target_user.email,
            "role": role,
            "specialization": target_user.specialization,
            "status": target_user.status,
        }

        # Prepare monthly performance data for the current year for the last 6 months.
        monthly_data = []
        now = timezone.now()
        current_year = now.year
        # Determine the starting month (if current month < number_of_months, start at January)
        number_of_months = 6
        start_month = max(1, now.month - number_of_months + 1)
        for month in range(start_month, now.month + 1):
            # Create a date label for the month
            label = datetime.date(current_year, month, 1).strftime("%B %Y")

            if role == "developer":
                qs = Task.objects.filter(
                    assigned_to__user=target_user,
                    created_at__year=current_year,
                    created_at__month=month
                )
                total = qs.count()
                completed = qs.filter(status=TaskStatus.COMPLETED).count()

            elif role == "project manager":
                qs = Task.objects.filter(
                    created_by=target_user,
                    created_at__year=current_year,
                    created_at__month=month
                )
                total = qs.count()
                completed = qs.filter(status=TaskStatus.COMPLETED).count()
            
            elif role == "qa":
                qs = TestCase.objects.filter(
                    created_by=target_user,
                    created_at__year=current_year,
                    created_at__month=month
                )
                total = qs.count()
                # For QA, we consider a test finished if at least one assignment is completed.
                finished = UserTestCase.objects.filter(
                    test_case__created_by=target_user,
                    assigned_at__year=current_year,  # Changed from created_at to assigned_at
                    assigned_at__month=month,
                    status=UserTestCaseStatus.COMPLETED
                ).count()
                completed = finished
            
            elif role == "test engineer":
                qs = UserTestCase.objects.filter(
                    assigned_to__user=target_user,
                    assigned_at__year=current_year,
                    assigned_at__month=month
                )
                total = qs.count()
                completed = qs.filter(status=UserTestCaseStatus.COMPLETED).count()
            else:
                total = 0
                completed = 0

            efficiency = (completed / total) * 100 if total > 0 else 0
            monthly_data.append({
                "month": label,
                "total": total,
                "completed": completed,
                "efficiency": round(efficiency, 2)
            })
        
        data = {
            "user_details": user_details,
            "monthly_performance": monthly_data
        }
        return Response(data, status=status.HTTP_200_OK)


# list bug by modules

class ModuleBugListView(ListAPIView):
    serializer_class = BugSerializer

    def get_queryset(self):
        module_id = self.kwargs.get('module_id')
        module = get_object_or_404(Module, id=module_id)
        return Bug.objects.filter(test_case_result__test_case__module = module)
    


#project manager report
class ProjectManagerGraphView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProjectBasicSerializer

    def get_queryset(self):
        return Project.objects.filter(
            project_lead = self.request.user
        ).exclude(
            status=ProjectStatus.COMPLETED
        )
    

#project manager report project status
class ProjectStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, project_id):

        project = get_object_or_404(Project, id=project_id)

        # Tasks
        tasks_qs = Task.objects.filter(module__project=project)
        total_tasks = tasks_qs.count()
        completed_tasks = tasks_qs.filter(status=TaskStatus.COMPLETED).count()
        pending_tasks = total_tasks - completed_tasks

        #Modules
        modules_qs = project.modules.all()
        total_modules = modules_qs.count()
        completed_modules = modules_qs.filter(status=ModuleStatus.COMPLETED).count()
        pending_modules = total_modules - completed_modules

        # Test Cases
        testcases_qs = TestCase.objects.filter(module__project=project)
        total_testcases = testcases_qs.count()
        completed_testcases = testcases_qs.filter(status=TestCaseStatus.COMPLETED).count()
        failed_testcases = testcases_qs.filter(status= TestCaseStatus.FAILED).count()
        pending_testcases = total_testcases - completed_testcases

        # Bugs
        bugs_qs = Bug.objects.filter(test_case_result__test_case__module__project=project)
        total_bugs = bugs_qs.count()

        # Prepare the response data
        data = {
            "project_id": project.id,
            "project_name": project.project_name,
            "project_status": project.status,
            "overall_progress": project.progress,
            "metrics": {
                "tasks": {
                    "total": total_tasks,
                    "completed": completed_tasks,
                    "pending": pending_tasks
                },
                "modules": {
                    "total": total_modules,
                    "completed": completed_modules,
                    "pending": pending_modules
                },
                "test_cases": {
                    "total": total_testcases,
                    "completed": completed_testcases,
                    "failed": failed_testcases,
                    "pending": pending_testcases
                },
                "bugs": {
                    "total": total_bugs
                }
            }
        }
        return Response(data, status=200)


from .serializers import BugTaskSerializer
#assign bug to developer and fix task

class AssignBugView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, bug_id):

        user = request.user
        if not user.role or user.role.role_name.lower() != "project manager":
            return Response({"error": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        
        # get bug and its module
        bug = get_object_or_404(Bug, id= bug_id)
        try:
            bug_module = bug.test_case_result.test_case.module
        except AttributeError:
            return Response({"error": "Module could not be found for this bug."}, status=status.HTTP_400_BAD_REQUEST)
        
        #Desirilize the task data from the request
        serializer = BugTaskSerializer(data = request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        #Get developer id and ensure they are part of the project
        developer_id = request.data.get("assigned_to")
        print("developer_id", developer_id)

        if not developer_id:
            return Response({"error":"Developer id is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        project = bug_module.project
        print("project : ", project)
        project_team_member = ProjectTeam.objects.filter(project = project, user_id = developer_id, status = "active").first()
        print("project_team_member:", project_team_member)
        if not project_team_member:
            return Response({"error":"Developer not found in the project team"}, status=status.HTTP_400_BAD_REQUEST)
        
        #save the task
        task = serializer.save(
            module = bug_module,
            created_by = user,
            assigned_to = project_team_member,
            task_type = TaskType.BUG_FIX
        )

        #Link task to bug and update status
        bug.fix_task = task
        bug.assigned_to = project_team_member
        bug.status = "in_progress"
        bug.save()

        #save optional task comments
        comment_text = request.data.get("comment")
        if comment_text:
            TaskComment.objects.create(
                user = user,
                task = task,
                content = comment_text
            )

        #Notify the developer
        Notification.objects.create(
            user = project_team_member.user,
            message = f"You have been assigned a fix task for bug '{bug.title}' in project '{project.project_name}'."
        )

        return Response({
            "message":"Task assigned and linked to bug successfully.",
            "task": serializer.data
        }, status=status.HTTP_201_CREATED)



from .serializers import TaskBugSerializer

#developer dashboard bug fix task

class DeveloperTaskWithBugsView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TaskBugSerializer

    def get_queryset(self):
        # Get the active project team records for the logged-in developer.
        project_team_records = ProjectTeam.objects.filter(user=self.request.user, status="active")
        # Filter tasks that are assigned to these project team records
        # and that have at least one related bug (via the "bug_fixes" related name)
        return Task.objects.filter(
            assigned_to__in=project_team_records,
            bug_fixes__isnull=False
        ).distinct()
    


# detailed task wilth bugs
class DeveloperTaskDetailView(RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TaskBugSerializer
    lookup_field = "id"

    def get_queryset(self):
        # Retrieve all ProjectTeam records for the logged-in developer (active team memberships)
        project_team_records = ProjectTeam.objects.filter(user=self.request.user, status="active")
        # Return tasks assigned to these project team records.
        return Task.objects.filter(assigned_to__in=project_team_records)

    def retrieve(self, request, *args, **kwargs):
        # Get the task from our filtered queryset using the provided task_id.
        task = get_object_or_404(self.get_queryset(), id=kwargs.get("task_id"))
        serializer = self.get_serializer(task)
        return Response(serializer.data)
    

#update bug status

class UpdateBugStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, bug_id):
        if request.user.role.role_name.lower() != "developer":
            return Response({"error": "Only developers can update bug status"}, status=status.HTTP_403_FORBIDDEN)

        bug = get_object_or_404(Bug, id=bug_id)

        # Verify the bug is assigned to the developer
        project = bug.test_case_result.test_case.module.project
        project_team_record = ProjectTeam.objects.filter(user=request.user, project=project, status="active").first()
        if not project_team_record or bug.assigned_to != project_team_record:
            return Response({"error": "Bug is not assigned to you."}, status=status.HTTP_403_FORBIDDEN)

        # Get the new fix status from request data
        new_fix_status = request.data.get("fix_status")
        if new_fix_status not in dict(bug.FIX_STATUS_CHOICES).keys():
            return Response({"error": "Invalid fix status."}, status=status.HTTP_400_BAD_REQUEST)

        # Optionally get resolution notes
        resolution_notes = request.data.get("resolution_notes", "")

        # Update the bug's fix status
        bug.fix_status = new_fix_status

        # Change bug status based on fix_status
        if new_fix_status == "in_progress":
            bug.status = "in_progress"

        elif new_fix_status == "fixed":
            bug.fixed_at = timezone.now()
            bug.status = "resolved"
            bug.resolution_notes = resolution_notes

        elif new_fix_status == "closed":
            bug.fixed_at = timezone.now()
            bug.status = "closed"
            bug.resolution_notes = resolution_notes

        bug.save()

        # Check if any bug related to the test case is fixed
        test_case = bug.test_case_result.test_case
        related_bugs = bug.test_case_result.bugs.all()
        if any(b.fix_status == "fixed" for b in related_bugs):
            # Update test case status to ASSIGNED if not already set
            if test_case.status != TestCaseStatus.ASSIGNED:
                test_case.status = TestCaseStatus.ASSIGNED
                test_case.save()

            # Update all UserTestCase statuses for this test case to "todo"
            user_test_cases = test_case.assigned_users.all()
            for utc in user_test_cases:
                utc.status = UserTestCaseStatus.TODO
                utc.save()

            # For granular retesting, update only the failed test step results to "not_run"
            failed_steps = UserTestStepResult.objects.filter(
                user_test_case__test_case=test_case,
                status="fail"
            )
            for step_result in failed_steps:
                step_result.status = "not_run"
                step_result.save()
            # Optionally, you can send a notification to the test engineer(s).

        serializer = BugSerializer(bug)
        return Response(serializer.data, status=status.HTTP_200_OK)



# qa dashboard report
class QAReportDashboard(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        user = request.user
        user_test_cases = TestCase.objects.filter(created_by=user)

        total = user_test_cases.count()
        passed = user_test_cases.filter(status=TestCaseStatus.COMPLETED).count()
        failed = user_test_cases.filter(status=TestCaseStatus.FAILED).count()
        pass_rate = (passed / total * 100) if total > 0 else 0

        # Retrieve the most recent 5 failed test cases with project and module details.
        recent_failed_qs = user_test_cases.filter(status=TestCaseStatus.FAILED).order_by('-created_at')[:5]
        recent_failed = []
        for test in recent_failed_qs:
            recent_failed.append({
                'test_id': test.test_id,
                'test_title': test.test_title,
                'test_description': test.test_description,
                'project_name': test.module.project.project_name,  # Fetching project name
                'module_name': test.module.module_name,            # Fetching module name
                'created_at': test.created_at,
                'due_date': test.due_date,
            })

        return Response({
            'total_test_cases': total,
            'passed_test_cases': passed,
            'failed_test_cases': failed,
            'pass_rate': round(pass_rate, 2),
            'recent_failed_test_cases': recent_failed
        })
    
#qa dashboard failed test case

class QaFailedTestcaseWithBugs(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        user = request.user
        # Filter failed test cases created by the authenticated QA user.
        failed_test_cases = TestCase.objects.filter(created_by=user, status=TestCaseStatus.FAILED)

        results = []
        for test in failed_test_cases:
            bugs_list = []
            # A test case can have multiple test results; each may have associated bugs.
            for test_result in test.test_results.all():
                # Serialize all bugs related to the test result.
                serialized_bugs = BugSerializer(test_result.bugs.all(), many=True).data
                bugs_list.extend(serialized_bugs)

            # Determine the last run (most recent TestCaseResult) for the test case.
            last_run_obj = test.test_results.order_by('-execution_date').first()
            last_run = None
            if last_run_obj:
                last_run = {
                    'result': last_run_obj.result,
                    'execution_date': last_run_obj.execution_date,
                    'remarks': last_run_obj.remarks,
                    'executed_by': last_run_obj.executed_by.username,
                }

            results.append({
                'test_id': test.test_id,
                'test_title': test.test_title,
                'test_description': test.test_description,
                'project_name': test.module.project.project_name,
                'module_name': test.module.module_name,
                'created_at': test.created_at,
                'due_date': test.due_date,
                'bugs': bugs_list,
                'last_run': last_run,
            })

        return Response(results)



@api_view(["GET"])
@permission_classes([IsAuthenticated])
def users_by_experience(request):
    """API to list users with the highest experience, excluding admins"""
    users = User.objects.filter(date_joined__isnull=False).exclude(is_superuser=True).order_by("date_joined")
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated

from .models import Project, User, ProjectTeam
from .serializers import ProjectTeamSerializer  # Create one if needed

class AddUsersToProjectView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, project_id):
        # Retrieve the project by id (or by any unique identifier)
        project = get_object_or_404(Project, id=project_id)

        # Check permission: only allow if the request.user is a project manager or is the project lead.
        if (request.user.role.role_name.lower() != "project manager" and 
            project.project_lead != request.user):
            return Response(
                {"error": "Permission Denied: Only a project manager or project lead can add users."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get the list of user IDs from the request payload.
        user_ids = request.data.get("user_ids")
        if not user_ids or not isinstance(user_ids, list):
            return Response(
                {"error": "A list of user IDs is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        added_users = []
        errors = []

        # Iterate over each user ID to add to the project.
        for user_id in user_ids:
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                errors.append({"user_id": user_id, "error": "User does not exist."})
                continue

            # Check if user is already in the project team with an active status.
            if ProjectTeam.objects.filter(project=project, user=user, status="active").exists():
                errors.append({"user_id": user_id, "error": "User is already part of the project."})
                continue

            # Create the new project team assignment.
            project_team_entry = ProjectTeam.objects.create(project=project, user=user, status="active")
            added_users.append({
                "user_id": user.id,
                "username": user.username,
                "project_team_id": project_team_entry.id
            })

        # Prepare the response data.
        response_data = {
            "added_users": added_users,
            "errors": errors
        }
        return Response(response_data, status=status.HTTP_201_CREATED)
    
#list the projects which have bugs, in project manager assign bug dashboard

class ProjectWithBugsView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProjectBasicSerializer

    def get_queryset(self):
        # Filter projects where there is at least one bug (through the chain of relationships)
        return Project.objects.filter(
            modules__test_cases__test_results__bugs__isnull=False
        ).distinct() 


# list the modules in a project with bugs, in project manager assign bug dashboard
class ModuleWithBugsView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ModuleSerializer

    def get_queryset(self, *args, **kwargs):
        project_id = self.kwargs.get('project_id')
        return Module.objects.filter(
            project__id = project_id,
            test_cases__test_results__bugs__isnull = False
        ).distinct()