from rest_framework import serializers
from .models import User, Role, Project, ProjectTeam, Module, Task, Bug, Notification, TestType, TestCase, UserTestCase
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
from django.contrib.auth.password_validation import validate_password
from django.utils.timezone import localtime
from datetime import date


# Login
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length = 100)
    password = serializers.CharField(write_only = True)


# password reset
class PasswordResetSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only = True)

    def validate(self, data):
        if data.get("new_password") != data.get("confirm_password"):
            raise serializers.ValidationError({"confirm_password":"Passwords do not match."})
        return data
    

# create new user
class CreateUserSerializer(serializers.ModelSerializer):
    role = serializers.PrimaryKeyRelatedField(queryset = Role.objects.all(), required = True)
    password = serializers.CharField(write_only = True, required = True)
    extra_kwargs = {'password': {'write_only': True}}

    class Meta:
        model = User
        fields = ['user_id','first_name', 'last_name', 'email', 'role', 'profile_picture', 'status', 'password', 'specialization']
    
    def create(self, validated_data):
        email = validated_data['email']
        validated_data['username'] = email.split('@')[0]
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)
    

# user list
class UserSerializer(serializers.ModelSerializer):
    role = serializers.StringRelatedField()
    name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id','user_id', 'name', 'first_name', 'last_name', 'email', 'role','profile_picture', 'status', 'specialization']


    def get_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip()

    
    
# Edit user
class EditSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['user_id','first_name', 'last_name', 'email', 'role', 'status']
        extra_kwargs = {
            'email': {'read_only': True},
            'username': {'read_only': True},
            'password': {'write_only':True, 'required': False},
            'profile_picture': {'read_only': True},
        }
    

# Change password
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only = True, required =True)
    new_password = serializers.CharField(write_only = True, required = True)
    confirm_new_password = serializers.CharField(write_only = True, required = True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not check_password(value, user.password):
            raise serializers.ValidationError("Old password is incorrect.")
        return value
    
    def validate_new_password(self, value):
        validate_password(value)
        return value
    
    def validate(self, data):
        if data['new_password'] != data['confirm_new_password']:
            raise serializers.ValidationError({"confirm_new_password": "Passwords do not match"})
        return data
    

# Role 
class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ['id', 'role_name']


# Add profile picture

class AddProfilePictureSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['profile_picture']
        extra_kwargs = {
            'profile_picture': {'write_only': True}
        }

    
# project team

class ProjectTeamSerializer(serializers.ModelSerializer):
    user_details = UserSerializer(source="user", read_only=True)  # Return full user details for output
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all()) #Accept user id
    class Meta:
        model = ProjectTeam
        fields = ['id', 'user', 'status', 'user_details']


# project  

class ProjectSerializer(serializers.ModelSerializer):
    team_members = ProjectTeamSerializer(many = True, write_only = True) # Expecting a list of team members
    project_team = ProjectTeamSerializer(source="projectteam_set", many=True, read_only=True)  # Return full team details

    
    class Meta:
        model = Project
        fields = ['project_id', 'project_name', 'project_description', 'project_lead', 'deadline', 'team_members', 'project_team']

    def create(self, validated_data):
        team_members_data = validated_data.pop('team_members', [])  # Extract team members
        created_by = self.context['request'].user  # Get the user who created the project
        project_lead = validated_data.get("project_lead", created_by)  # Assign lead if none

        validated_data['project_lead'] = project_lead

        
        project = Project.objects.create(created_by=created_by, **validated_data)
        
         # Add team members to the project team
        for member_data in team_members_data:
            ProjectTeam.objects.create(project=project, user=member_data["user"])  # Add each user to ProjectTeam

        return project
    

# project list in dashboard
class ProjectListSerializer(serializers.ModelSerializer):
    project_lead = UserSerializer()
    project_team = ProjectTeamSerializer(many = True)
    progress = serializers.ReadOnlyField()
    bugs_count = serializers.SerializerMethodField()
    created_date = serializers.SerializerMethodField()
    

    class Meta:
        model = Project
        fields = ["id","project_id", "project_name","project_description","project_lead","project_team", "progress","status","created_at","deadline","bugs_count", "created_date"]
    
    def get_bugs_count(self, obj):
        return Bug.objects.filter(test_case__module__project = obj).count()    
    
    def get_created_date(self, obj):
        return localtime(obj.created_at).strftime("%Y-%m-%d")


#project list task
class LeadProjectListSerializer(serializers.ModelSerializer):
    progress = serializers.ReadOnlyField()

    class Meta:
        model = Project
        fields = ["id","project_id", "project_name","project_description","project_lead", "progress","status","created_at","deadline"]


#Module serializer

class ModuleSerializer(serializers.ModelSerializer):
    project_deadline = serializers.DateField(source = "project.deadline", read_only = True)

    class Meta:
        model = Module
        fields = ["id", "Module_id", "module_name", "module_description", "due_date", "priority", "created_at", "project_deadline"]

    def validate_due_date(self, value):

        project = self.context.get("project")

        if not project:
            raise serializers.ValidationError("Project is required to validate due date.")

        if value and project.deadline and value > project.deadline:
            raise serializers.ValidationError("Module due date cannot exceed project deadline!")

        return value
    

# task serializer

class TaskSerializer(serializers.ModelSerializer):

    created_by = serializers.SerializerMethodField()
    assigned_to_name = serializers.SerializerMethodField()
    project_name = serializers.SerializerMethodField()  # Get project name
    module_name = serializers.SerializerMethodField()  # Get module name
    due_status = serializers.SerializerMethodField()


    class Meta:
        model = Task
        fields = ["id", "task_id", "task_name", "task_description", "assigned_to", "created_by", "priority","status", "created_at","updated_at","due_date", "assigned_to_name", "project_name", "module_name", "progress", "due_status" ]


    def get_assigned_to_name(self, obj):
        if obj.assigned_to and obj.assigned_to.user:  # Access user inside ProjectTeam
            return obj.assigned_to.user.get_full_name()
        return None
    
    
    def get_created_by(self, obj):
        return obj.created_by.get_full_name() if obj.created_by else None
    
    
    def get_project_name(self, obj):
        if obj.module and obj.module.project:
            return obj.module.project.project_name
        return None
    
    
    def get_module_name(self, obj):
        return obj.module.module_name if obj.module else None
    
    def get_due_status(self, obj):

        if obj.due_date:
            today = date.today()
            days_remaining = (obj.due_date - today).days

            if days_remaining == 0:
                return "Due today"
            elif days_remaining == 1:
                return "Due in 1 day"
            elif days_remaining > 1:
                return f"Due in {days_remaining} days"
            else:
                return "Overdue"
        
        return "No due date set"
    

    def validate_due_date(self, value):
        module = self.context.get("module")  # Get module from context
        if not module:
            raise serializers.ValidationError("Module is required to validate due date.")

        if value and module.due_date and value > module.due_date:
            raise serializers.ValidationError("Task due date cannot exceed module deadline!")

        return value


    
# list developer list    
class DeveloperSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()


    class Meta:
        model = User
        fields = ["id", "username", "email", "specialization", "profile_picture", "full_name"]

    def get_full_name(self, obj): 
        return f"{obj.first_name} {obj.last_name}".strip() if obj.first_name and obj.last_name else obj.username


# Notification

class NotificationSerializer(serializers.ModelSerializer):
    
    class Meta:
        model  = Notification
        fields = ["id", "user", "message", "status", "created_at"]



# test_type

class TestTypeSerializer(serializers.ModelSerializer):

    class Meta:
        model = TestType
        fields = ["id", "name"]

        

# test case serializer

class TestCaseSerializer(serializers.ModelSerializer):

    class Meta:
        model = TestCase
        fields = ["id", "test_id", "test_title", "test_description", "steps", "expected_result", "priority", "status", "test_type", "created_at", "updated_at", "precondition", "postcondition"]
        extra_kwargs = {"created_by" : {"read_only" : True}}

    


# test engineers list

class TestEngineersSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ["id", "username", "email", "profile_picture"]
