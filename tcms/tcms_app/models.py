from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
import random
from django.db.models import Count

# Create your models here.


#Role 

class Role(models.Model):
    role_name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.role_name
    

#User
    
class User(AbstractUser): 
    user_id = models.CharField(max_length=20, unique=True)
    role = models.ForeignKey(Role, on_delete=models.PROTECT)  
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)  
    email = models.EmailField(unique=True)  
    status = models.CharField(max_length=20, choices=[('active', 'Active'), ('inactive', 'Inactive')], default='active') 
    
    SPECIALIZATION_CHOICES = [
        ('frontend', 'Frontend Developer'),
        ('backend', 'Backend Developer'),
        ('fullstack', 'Fullstack Developer'),
        ('flutter', 'Flutter Developer'),
        ('react', 'React Developer'),
        ('python', 'Python Developer'),
    ]

    specialization = models.CharField(max_length=20, choices=SPECIALIZATION_CHOICES, null=True, blank=True)



    def save(self, *args, **kwargs):

        if self.role.role_name.lower() != "developer":
            self.specialization = None
            
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username
    
#Project Status

class ProjectStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    IN_PROGRESS = "in_progress", "In Progress"
    COMPLETED = "completed", "Completed"
    ARCHIVED = "archived", "Archived"

#Project

class Project(models.Model):
    project_id = models.CharField(max_length=6, unique=True)
    project_name = models.CharField(max_length= 255, unique = True)
    project_description = models.TextField()
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='created_projects')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    project_lead = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete = models.SET_NULL, null = True, blank = True, related_name = "lead_projects")
    deadline = models.DateField(null = True, blank=True)
    status = models.CharField(max_length = 20, choices = ProjectStatus.choices, default = ProjectStatus.PENDING)

    def save(self, *args, **kwargs):
        if not self.project_lead:
            self.project_lead = self.created_by

        # Ensure the instance is saved before querying related models

        is_new = self._state.adding  # Check if the instance is new

        super().save(*args, **kwargs)  # Save the project first

        if not is_new:  # Query related objects only if it's not a new project
            tasks = Task.objects.filter(module__project=self)
            test_cases = TestCase.objects.filter(module__project=self)

            if tasks.exists() and test_cases.exists():
                completed_tasks = tasks.filter(status=TaskStatus.COMPLETED).count()
                completed_tests = test_cases.filter(status=TestCaseStatus.APPROVED).count()

                if completed_tasks == tasks.count() and completed_tests == test_cases.count():
                    self.status = ProjectStatus.COMPLETED
                else:
                    self.status = ProjectStatus.IN_PROGRESS
            else:
                self.status = ProjectStatus.PENDING

        super().save(update_fields=['status'])

    def __str__(self):
        return self.project_name
    
    @property
    def progress(self):
        task_stats = Task.objects.filter(module__project=self).aggregate(
        total=Count('id'), completed=Count('id', filter=models.Q(status=TaskStatus.COMPLETED)))
    
        total = task_stats["total"]
        completed = task_stats["completed"]

        return round((completed / total) * 100, 2) if total > 0 else 0


#Project Team

class ProjectTeam(models.Model):
    project = models.ForeignKey(Project, on_delete = models.CASCADE, related_name = "project_team")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete = models.CASCADE, related_name = "user_project_team")
    status = models.CharField(max_length = 20, choices = [("active", "Active"), ("removed", "Removed")], default = "active")
    date_added = models.DateTimeField(auto_now_add = True)

    def __str__(self):
        return f"{self.user.username} in {self.project.project_name}"

#Module Priority

class ModulePriority(models.TextChoices):
    HIGH = "high", "High"
    MEDIUM = "medium", "Medium"
    LOW = "low", "Low"

# Module status
class ModuleStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    IN_PROGRESS = "in_progress", "In Progress"
    COMPLETED = "completed", "Completed"


# Module
class Module(models.Model):
    Module_id = models.CharField(max_length=20, unique=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='modules')
    module_name = models.CharField(max_length=255)
    module_description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    due_date = models.DateField(null=True, blank=True)
    priority = models.CharField(max_length=10, choices=ModulePriority.choices, default=ModulePriority.MEDIUM)
    status = models.CharField(max_length=15, choices=ModuleStatus.choices, default=ModuleStatus.PENDING)  # New Field


    def __str__(self):
        return f"{self.module_name} ({self.project.project_name})"
    
    @property
    def progress(self):
        tasks = Task.objects.filter(module=self)
        if tasks.count() == 0:
            return 0
        completed_tasks = tasks.filter(status=TaskStatus.COMPLETED).count()
        return round((completed_tasks / tasks.count()) * 100, 2)
    
    def save(self, *args, **kwargs):
        # First, save the instance if it's new
        is_new = self._state.adding  # Check if this is a new object
        super().save(*args, **kwargs)  

        # Now query tasks only if the instance is saved (existing in DB)
        if not is_new:
            tasks = Task.objects.filter(module=self)
            if tasks.exists():
                completed_tasks = tasks.filter(status=TaskStatus.COMPLETED).count()
                if completed_tasks == tasks.count():
                    self.status = ModuleStatus.COMPLETED
                else:
                    self.status = ModuleStatus.IN_PROGRESS
            else:
                self.status = ModuleStatus.PENDING
            
            # Save again to update the status
            super().save(update_fields=['status'])


#Task Priority
class TaskPriority(models.TextChoices):
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


#Task Status
class TaskStatus(models.TextChoices):
    TO_DO = "to_do", "To Do"
    IN_PROGRESS = "in_progress", "In Progress"
    BLOCKED = "blocked", "Blocked"
    COMPLETED = "completed", "Completed"

#Task 
class Task(models.Model):
    task_id = models.CharField(max_length=20, unique=True)
    module = models.ForeignKey(Module, on_delete=models.CASCADE, related_name="tasks")
    task_name = models.CharField(max_length=255)
    task_description = models.TextField()
    assigned_to = models.ForeignKey(ProjectTeam, on_delete=models.CASCADE, related_name="assigned_tasks")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="created_tasks")
    priority = models.CharField(max_length=10, choices=TaskPriority.choices, default=TaskPriority.MEDIUM)
    status = models.CharField(max_length=20, choices = TaskStatus.choices, default=TaskStatus.TO_DO)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    due_date = models.DateField(null = True, blank=True)
    progress = models.IntegerField(default=0)

    def update_progress(self):

        progress_mapping = {
            TaskStatus.TO_DO: 0,
            TaskStatus.IN_PROGRESS: 50,
            TaskStatus.COMPLETED: 100
        }
        self.progress = progress_mapping.get(self.status, 0)

 
    def save(self, *args, **kwargs):
        self.update_progress()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.task_name} ({self.module.module_name})"
    

#Notification 

class Notification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notifications")
    message = models.TextField()
    status = models.CharField(max_length=20, choices = [("read", "Read"), ("unread", "Unread")], default="unread")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification for {self.user.username}: {self.message}"
    

#Test type

class TestType(models.Model):
    name = models.CharField(max_length=50, unique=True)
    
    def __str__(self):
        return self.name


#test case 

class TestCasePriority(models.TextChoices):
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"

class TestCaseStatus(models.TextChoices):
    ASSIGNED = "assigned", "Assigned"
    COMPLETED = "completed", "Completed"

    
class TestCase(models.Model):
    test_id = models.CharField(max_length=20, unique=True)
    module = models.ForeignKey("Module", on_delete=models.CASCADE, related_name="test_cases")
    test_title = models.CharField(max_length=255)
    test_description = models.TextField()
    steps = models.TextField()
    expected_result = models.TextField()
    priority = models.CharField(max_length=10, choices=TestCasePriority.choices, default=TestCasePriority.MEDIUM)
    status = models.CharField(max_length=20, choices=TestCaseStatus.choices, default=TestCaseStatus.ASSIGNED)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="created_test_cases")
    test_type = models.ForeignKey("TestType", on_delete=models.CASCADE, related_name="test_cases")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    precondition = models.TextField(null=True, blank=True)  
    postcondition = models.TextField(null=True, blank=True) 


    def __str__(self):
        return f"{self.test_title} ({self.module.module_name})"
    

# user test case  
    
class UserTestCaseStatus(models.TextChoices):
    TODO = "todo", "To Do"
    IN_PROGRESS = "in_progress", "In Progress"
    COMPLETED = "completed", "Completed"


class UserTestCase(models.Model):
    test_case = models.ForeignKey(TestCase, on_delete=models.CASCADE, related_name="assigned_users")
    assigned_to = models.ForeignKey(ProjectTeam, on_delete=models.CASCADE, related_name="user_test_cases")
    status = models.CharField(max_length=20, choices=UserTestCaseStatus.choices, default=UserTestCaseStatus.TODO) 
    assigned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.test_case.test_title} -> {self.assigned_to.user.username}"

# task comment

class TaskComment(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='task_comments')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name="task_comments")

#test comment

class TestComment(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='test_comments')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    test = models.ForeignKey(TestCase, on_delete=models.CASCADE, related_name="test_comments")


# test result

class TestCaseResult(models.Model):
    test_case = models.ForeignKey(TestCase, on_delete=models.CASCADE, related_name="test_results")
    executed_by = models.ForeignKey(ProjectTeam, on_delete=models.CASCADE, related_name="executed_test_cases")
    result = models.CharField(max_length=20, choices=[("passed", "Passed"), ("failed", "Failed")], default="passed")
    execution_date = models.DateTimeField(auto_now_add=True)
    remarks = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.test_case.title} -> {self.result}"
    
# bug
    
class Bug(models.Model):
    bug_id = models.CharField(max_length=20, unique=True)
    test_case = models.ForeignKey(TestCase, on_delete=models.CASCADE, related_name="bugs")
    reported_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="reported_bugs")
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_bugs")
    title = models.CharField(max_length=255)
    description = models.TextField()
    priority = models.CharField(max_length=10, choices=TestCasePriority.choices, default=TestCasePriority.MEDIUM)
    status = models.CharField(max_length=20, choices=[("open", "Open"), ("in_progress", "In Progress"), ("resolved", "Resolved"), ("closed", "Closed")], default="open")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} ({self.status})"


#Attachment

class Attachment(models.Model):
    file = models.FileField(upload_to="attachments/")
    uploaded_at = models.DateTimeField(auto_now_add=True)

    # Generic ForeignKey-like behavior
    test_case_result = models.ForeignKey(TestCaseResult, on_delete=models.CASCADE, null=True, blank=True, related_name="attachments")
    bug = models.ForeignKey(Bug, on_delete=models.CASCADE, null=True, blank=True, related_name="attachments")

    def __str__(self):
        return f"Attachment {self.id} - {self.file.name}"