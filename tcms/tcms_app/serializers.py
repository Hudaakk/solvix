from rest_framework import serializers
from .models import User, Role, Project, ProjectTeam, Module, Task, Bug, Notification, TestType, TestCase, UserTestCase, TaskComment, TestComment, TestStep
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
        fields = ['id','user_id', 'name', 'first_name', 'last_name', 'email', 'role','profile_picture', 'status', 'specialization','username']


    def get_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip()

    
    
# Edit user
class EditSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['user_id','first_name', 'last_name','role', 'status', "specialization"]
        extra_kwargs = {
            'email':{'read_only':True},
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
        return Bug.objects.filter(test_case_result__test_case__module__project=obj).count()
    

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
    comments = serializers.SerializerMethodField()


    class Meta:
        model = Task
        fields = ["id", "task_id", "task_name", "task_description", "assigned_to", "created_by", "priority","status", "created_at","updated_at","due_date", "assigned_to_name", "project_name", "module_name", "progress", "due_status" , "comments","document"]


    def get_assigned_to_name(self, obj):
        if obj.assigned_to and obj.assigned_to.user:  # Access user inside ProjectTeam
            return obj.assigned_to.user.get_full_name()
        return None
    
    def get_comments(self, obj):
        comments = obj.task_comments.all().order_by("-created_at")
        return TaskCommentSerializer(comments, many = True).data if comments else []
    
    
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
    

    
#Task comment serializer

class TaskCommentSerializer(serializers.ModelSerializer):

    user_name = serializers.SerializerMethodField()

    class Meta:
        model = TaskComment
        fields = ["id", "user_name", "content", "created_at"]

    def get_user_name(self, obj):
        return obj.user.get_full_name() if obj.user else "Unknown User"



    
# list developer list 
   
class DeveloperSerializer(serializers.ModelSerializer):

    full_name = serializers.SerializerMethodField()
    project_team_id = serializers.IntegerField(source="id")  # Get the ProjectTeam ID
    id = serializers.IntegerField(source="user.id")
    username = serializers.CharField(source="user.username")
    email = serializers.EmailField(source="user.email")
    specialization = serializers.CharField(source="user.specialization", allow_null=True)

    class Meta:
        model = ProjectTeam  # Use ProjectTeam instead of User
        fields = ["project_team_id", "id", "username", "email", "specialization", "full_name"]

    def get_full_name(self, obj):
        user = obj.user
        return f"{user.first_name} {user.last_name}".strip() if user.first_name and user.last_name else user.username


# Notification

class NotificationSerializer(serializers.ModelSerializer):
    
    class Meta:
        model  = Notification
        fields = ["id", "user", "message", "status", "created_at"]


from .models import UserTestStepResult, UserTestCaseStatus


class UserTestStepResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserTestStepResult
        fields = ["id", "status", "execution_date", "remarks"]


# test step serializer
class TestStepSerializer(serializers.ModelSerializer):
    status_details = UserTestStepResultSerializer(source="user_results", many=True, read_only=True)

    class Meta:
        model = TestStep
        fields = ["id", "step_number", "step_description", "expected_result", "status_details"]

    # def get_status_details(self, obj):
    #     request = self.context.get("request", None)

    #     if request and request.user.is_authenticated:
    #         user = request.user
    #         user_test_case = UserTestCase.objects.filter(
    #             test_case=obj.test_case, assigned_to__user=user
    #         ).first()

    #         if user_test_case:
    #             user_test_step_result = UserTestStepResult.objects.filter(
    #                 user_test_case=user_test_case, test_step=obj
    #             ).first()

    #             if user_test_step_result:
    #                 return UserTestStepResultSerializer(user_test_step_result).data

    #     # Default response if no result found
    #     return {
    #         "id": None,
    #         "status": "not_run",
    #         "execution_date": None,
    #         "remarks": "No remarks"
    #     }

# test_type

class TestTypeSerializer(serializers.ModelSerializer):

    class Meta:
        model = TestType
        fields = ["id", "name"]

        

class TestCaseSerializer(serializers.ModelSerializer):
    test_type_name = serializers.CharField(source="test_type.name", read_only=True)
    assigned_users = serializers.SerializerMethodField()
    created_by = serializers.SerializerMethodField()
    progress = serializers.SerializerMethodField()
    due_status = serializers.SerializerMethodField()
    test_comments = serializers.SerializerMethodField()
    test_steps = TestStepSerializer(many = True, read_only = True)
    module_name = serializers.CharField(source="module.module_name", read_only=True)
    project_name = serializers.CharField(source="module.project.project_name", read_only=True)
    user_test_case_id = serializers.SerializerMethodField()  # New field



    class Meta:
        model = TestCase
        fields = [
            "id", "test_id", "test_title", "test_description",
            "priority", "status", "test_type", "created_at", "updated_at",
            "precondition", "postcondition", "test_type_name", "assigned_users", "created_by", "progress", "due_date", "due_status", "test_comments", "test_steps", 
            "module_name","project_name", "user_test_case_id"
        ]
        extra_kwargs = {"created_by": {"read_only": True}}

    def get_assigned_users(self, obj):

        #Retrieve all users assigned to the test case.

        user_test_cases = UserTestCase.objects.filter(test_case=obj)
        return [
            {
                "user_id": utc.assigned_to.user.id,
                "username": utc.assigned_to.user.get_full_name(),
                "email": utc.assigned_to.user.email,
                "status": utc.status
            }
            for utc in user_test_cases
        ]

    def get_created_by(self, obj):
        if obj.created_by:
            return f"{obj.created_by.first_name} {obj.created_by.last_name}".strip()
        return None
    

    def get_progress(self, obj):
        return obj.get_progress()
    
    def get_due_status(self, obj):
        return obj.get_due_date()
    
    def get_test_comments(self, obj):
        comments = obj.test_comments.all().order_by("-created_at")
        return TestCommentSerializer(comments, many = True).data
    
    def get_user_test_case_id(self, obj):
        request = self.context.get("request")
        if not request:
            return None
        user = request.user
        try:
            utc = UserTestCase.objects.get(test_case=obj, assigned_to__user=user)
            return utc.id
        except UserTestCase.DoesNotExist:
            return None



# test engineers list

class TestEngineersSerializer(serializers.ModelSerializer):

    full_name = serializers.SerializerMethodField()
    project_team_id = serializers.IntegerField(source="id")  # Get the ProjectTeam ID
    user_id = serializers.IntegerField(source="user.id")
    username = serializers.CharField(source="user.username")
    email = serializers.EmailField(source="user.email")
    specialization = serializers.CharField(source="user.specialization", allow_null=True)


    class Meta:
        model = ProjectTeam  
        fields = ["project_team_id", "user_id", "username", "email", "specialization", "full_name"]

    
    
    def get_full_name(self, obj):
        user = obj.user
        return f"{user.first_name} {user.last_name}".strip() if user.first_name and user.last_name else user.username
    



class AssignedTestCaseSerializer(serializers.ModelSerializer):
    user_test_case_id = serializers.IntegerField(source = "id")
    test_case = TestCaseSerializer(read_only=True)  # Use the full TestCaseSerializer
    progress = serializers.SerializerMethodField()

    class Meta:
        model = UserTestCase
        fields = ["user_test_case_id","id", "test_case", "progress"]


    def get_progress(self, obj):
        return obj.test_case.get_progress()
    




# test comment serializer
class TestCommentSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source = "user.get_full_name", read_only = True)

    class Meta:
        model = TestComment
        fields = ["id", "user_name", "content", "created_at"]



# TE recent test

class UserTestCaseSerializer(serializers.ModelSerializer):
    test_case_id = serializers.IntegerField(source = "test_case.id")
    test_case_test_id = serializers.CharField(source = "test_case.test_id")
    test_case_title = serializers.CharField(source="test_case.test_title")
    test_case_status = serializers.CharField(source="test_case.status")
    module_name = serializers.CharField(source="test_case.module.module_name")
    assigned_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")

    class Meta:
        model = UserTestCase
        fields = ["test_case_id","test_case_title", "test_case_status", "module_name", "status", "assigned_at", "test_case_test_id"]



    

# ProjectTaskSerializer

class ProjectTaskSerializer(serializers.ModelSerializer):

    module = serializers.StringRelatedField()
    assigned_to = serializers.StringRelatedField()

    class Meta:
        model = Task
        fields = ["task_id", "task_name", "task_description", "assigned_to", "priority", "status", "created_at", "due_date"]


class ProjectDetailSerializer(serializers.ModelSerializer):
    project_team = ProjectTeamSerializer(many=True, read_only=True)
    modules = ModuleSerializer(many=True, read_only=True)
    progress = serializers.ReadOnlyField()
    project_lead = UserSerializer(read_only = True)

    class Meta:
        model = Project
        fields = ["project_id", "project_name", "project_description", "created_by", "project_lead", "deadline", "status", "progress", "project_team", "modules", "project_lead"]



# UserTeststep serializer
class UserTestStepResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserTestStepResult
        fields = ["id","status", "remarks"]

    def validate(self, data):

        if data.get("status") not in ["pass", "fail"] and not data.get("marks"):
            raise serializers.ValidationError({"remarks": "Remarks are required when marking a step as pass or fail"})
        return data

    def update(self, instance, validated_data):
        instance.status = validated_data.get("status", instance.status)
        instance.remarks = validated_data.get("remarks", instance.remarks)
        instance.save()

        # Update UserTestCase status based on test step results
        user_test_case = instance.user_test_case
        
        if user_test_case.status == UserTestCaseStatus.TODO:
            user_test_case.status = UserTestCaseStatus.IN_PROGRESS
            user_test_case.save()
        
        
        # If all steps are passed, mark as completed
        all_steps = user_test_case.user_test_step_results.all()
        if all_steps.exclude(status__in=["pass", "fail"]).count() == 0:  # No remaining "not_run" steps
            user_test_case.status = UserTestCaseStatus.COMPLETED
            user_test_case.save()

        return instance


from .models import Attachment, Bug, TestCaseResult

# A brief serializer for users to return full name and id.
class UserBriefSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "full_name"]

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip()
    


class AttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attachment
        fields = ["id", "file", "uploaded_at"]




class TestCaseResultBriefSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestCaseResult
        fields = ["id", "result", "remarks", "execution_date"]


class BugSerializer(serializers.ModelSerializer):
    reported_by = UserBriefSerializer(read_only=True)
    assigned_to = ProjectTeamSerializer(read_only=True)
    attachments = AttachmentSerializer(many=True, read_only=True)
    test_case_result = TestCaseResultBriefSerializer(read_only=True)
    fix_task = serializers.SerializerMethodField()


    class Meta:
        model = Bug
        fields = ["id", "bug_id", "title", "description","priority", "status", "created_at", "severity","steps_to_reproduce", "environment", "reported_by", "assigned_to", "attachments", "test_case_result","fix_task","fix_status"]

    
    def get_fix_task(self, obj):
        return obj.fix_task.task_name if obj.fix_task else None
    





#Admin dashboard project management
class ProjectBasicSerializer(serializers.ModelSerializer):
    progress = serializers.ReadOnlyField()
    class Meta:
        model = Project
        fields = ['project_id', 'project_name', 'project_description','id', "progress"]



# user project serializer

class UserWithProjectsSerializer(serializers.ModelSerializer):
    associated_projects = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'associated_projects']

    def get_associated_projects(self, obj):
        # Get projects where the user is the creator
        created_projects = list(obj.created_projects.all())
        # Get projects where the user is the project lead (via the related_name "lead_projects")
        lead_projects = list(obj.lead_projects.all())
        # Get projects where the user is in the project team (via the related_name "user_project_team")
        team_projects = [pt.project for pt in obj.user_project_team.all()]

        # Combine all projects and remove duplicates based on project_id.
        all_projects_dict = {}
        for p in created_projects + lead_projects + team_projects:
            all_projects_dict[p.project_id] = p
        all_projects = list(all_projects_dict.values())

        # Return a list of dictionaries with the project id and name.
        return [{"project_id": p.project_id, "project_name": p.project_name} for p in all_projects]
    


# task bug serializer

class TaskBugSerializer(serializers.ModelSerializer):
    # Use the 'source' parameter to tell the serializer to use the related name from Bug
    bugs = serializers.SerializerMethodField()

    class Meta:
        model = Task
        fields = [
            "task_id","id", "task_name", "task_description", "priority", "status",
            "due_date", "document", "progress", "bugs"
        ]

    
    def get_bugs(self, obj):
        # Get the bugs related to this task using the related_name "bug_fixes".
        # We include only bugs that still need fixing.
        pending_bugs = obj.bug_fixes.filter(
            fix_status__in=["pending", "in_progress"],
            status__in=["open", "in_progress", "resolved"]
        )
        # Serialize the filtered bugs.
        return BugSerializer(pending_bugs, many=True).data



# class DeveloperTaskDetailSerializer(serializers.ModelSerializer):
#     # Use the source 'bug_fixes' to pull in related bugs (via the foreign key in Bug).
#     bugs = BugSerializer(many=True, read_only=True, source="bug_fixes")

#     class Meta:
#         model = Task
#         fields = [
#             "task_id",
#             "task_name",
#             "task_description",
#             "priority",
#             "status",
#             "due_date",
#             "document",
#             "progress",
#             "bugs",
#         ]