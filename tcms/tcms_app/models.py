from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils import timezone
from django.db.models import Count
from datetime import date

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

    def experience_in_months(self):
        """Calculate experience in months from date_of_joining to today."""
        if self.date_joined:
            today = date.today()
            total_months = (today.year - self.date_joined.year) * 12 + (today.month - self.date_joined.month)
            return max(total_months, 0)  # Ensures no negative values
        return 0
        
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
        # Handle archived projects first
        if self.status == ProjectStatus.ARCHIVED:
            super().save(*args, **kwargs)
            return

        # Set project lead if missing
        if not self.project_lead:
            self.project_lead = self.created_by

        # Initial save to create relationships
        super().save(*args, **kwargs)

        # New status determination logic
        has_modules = self.modules.exists()
        has_tests = TestCase.objects.filter(module__project=self).exists()

        if self.status != ProjectStatus.ARCHIVED:
            if has_modules or has_tests:
                new_status = ProjectStatus.IN_PROGRESS
                
                # Calculate actual progress
                total_modules = self.modules.count()
                completed_modules = self.modules.filter(status=ModuleStatus.COMPLETED).count()
                module_progress = (completed_modules / total_modules * 100) if total_modules else 0

                test_cases = TestCase.objects.filter(module__project=self)
                total_tests = test_cases.count()
                completed_tests = test_cases.filter(status=TestCaseStatus.COMPLETED).count()
                test_progress = (completed_tests / total_tests * 100) if total_tests else 0

                # Only mark completed if both are 100%
                if module_progress == 100 and test_progress == 100:
                    new_status = ProjectStatus.COMPLETED
            else:
                new_status = ProjectStatus.PENDING

            # Update status if changed
            if self.status != new_status:
                self.status = new_status
                super().save(update_fields=['status', 'updated_at'])

    @property
    def progress(self):
        # Keep original progress calculation for reporting
        module_qs = self.modules.all()
        total_modules = module_qs.count()
        module_progress = (module_qs.filter(status=ModuleStatus.COMPLETED).count() / total_modules * 100) if total_modules else 0

        test_qs = TestCase.objects.filter(module__project=self)
        total_tests = test_qs.count()
        test_progress = (test_qs.filter(status=TestCaseStatus.COMPLETED).count() / total_tests * 100) if total_tests else 0

        combined_progress = (module_progress + test_progress) / 2
        return round(combined_progress, 2)

    
    
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
    status = models.CharField(max_length=15, choices=ModuleStatus.choices, default=ModuleStatus.PENDING) 
    is_deleted = models.BooleanField(default=False)


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

#Task Type
class TaskType(models.TextChoices):
    MODULE = "module", "Module"
    BUG_FIX = "bug_fix", "Bug Fix"


#Task 
class Task(models.Model):
    task_id = models.CharField(max_length=20, unique=True)
    module = models.ForeignKey(Module, on_delete=models.CASCADE, related_name="tasks")
    task_name = models.CharField(max_length=255)
    task_description = models.TextField()
    assigned_to = models.ForeignKey(ProjectTeam, on_delete=models.CASCADE, related_name="assigned_tasks")
    document = models.FileField(upload_to="task_documents/", null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="created_tasks")
    priority = models.CharField(max_length=10, choices=TaskPriority.choices, default=TaskPriority.MEDIUM)
    status = models.CharField(max_length=20, choices = TaskStatus.choices, default=TaskStatus.TO_DO)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    due_date = models.DateField(null = True, blank=True)
    progress = models.IntegerField(default=0)
    task_type = models.CharField(max_length=20, choices=TaskType.choices, default=TaskType.MODULE )
    is_deleted = models.BooleanField(default=False)

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
    FAILED = "failed", "Failed"
    COMPLETED = "completed", "Completed"
    REASSIGNED = "reassigned", "Reassigned"

    
class TestCase(models.Model):
    test_id = models.CharField(max_length=20, unique=True)
    module = models.ForeignKey("Module", on_delete=models.CASCADE, related_name="test_cases")
    test_title = models.CharField(max_length=255)
    test_description = models.TextField()
    priority = models.CharField(max_length=10, choices=TestCasePriority.choices, default=TestCasePriority.MEDIUM)
    status = models.CharField(max_length=20, choices=TestCaseStatus.choices, default=TestCaseStatus.ASSIGNED)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="created_test_cases")
    test_type = models.ForeignKey("TestType", on_delete=models.CASCADE, related_name="test_cases")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    precondition = models.TextField(null=True, blank=True)  
    postcondition = models.TextField(null=True, blank=True)
    due_date = models.DateField(null=True, blank=True)


    def __str__(self):
        return f"{self.test_title} ({self.module.module_name})"
    

    def get_progress(self):
        assigned_users = self.assigned_users.all()  # UserTestCase instances
        total_users = assigned_users.count()
        if total_users == 0:
            return 0

        completed_users = assigned_users.filter(status=UserTestCaseStatus.COMPLETED).count()
        progress = int((completed_users / total_users) * 100)

        if completed_users == total_users and total_users > 0:
        # Check if each assigned user has a TestCaseResult and if it passed.
            all_passed = all(
                utc.test_result is not None and utc.test_result.result == "passed"
                for utc in assigned_users
            )
            if all_passed:
                self.status = TestCaseStatus.COMPLETED
            else:
                self.status = TestCaseStatus.FAILED
            self.save()

        return progress





    def get_due_date(self):
        if not self.due_date:
            return "No due date set"
        today = timezone.now().date()
        days_left = (self.due_date - today).days

        if days_left > 1:
            return f"{days_left} days left"
        elif days_left == 1:
            return "1 day left"
        elif days_left == 0:
            return "Due today"
        else:
            return f"Overdue by {-days_left} days"


# Test step
class TestStep(models.Model):
    test_case = models.ForeignKey(TestCase, on_delete=models.CASCADE, related_name="test_steps")
    step_number = models.PositiveIntegerField()
    step_description = models.TextField()
    expected_result = models.TextField()
    

    class Meta:
        ordering = ["step_number"]
        unique_together = ("test_case", "step_number")
        

    def __str__(self):
        return f"s{self.step_number} for {self.test_case.test_title}"


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
    updated_at = models.DateTimeField(auto_now=True)  

    def __str__(self):
        return f"{self.test_case.test_title} -> {self.assigned_to.user.username}"
    
    @property
    def test_result(self):
        return TestCaseResult.objects.filter(
            test_case=self.test_case, 
            executed_by=self.assigned_to.user
        ).last()



# user test step result
class UserTestStepResult(models.Model):
    user_test_case = models.ForeignKey(UserTestCase, on_delete=models.CASCADE, related_name="user_test_step_results")
    test_step = models.ForeignKey(TestStep, on_delete=models.CASCADE, related_name="user_results")
    status = models.CharField(
        max_length=10,
        choices=[("pass", "Pass"), ("fail", "Fail"), ("not_run", "Not Run")],
        default="not_run"
    )
    execution_date = models.DateTimeField(auto_now_add=True)
    remarks = models.TextField(blank=True, null=True)


    def __str__(self):
        return f"{self.user_test_case.assigned_to.user.username} -> Step {self.test_step.step_number} -> {self.status}"




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
    executed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="test_results")
    result = models.CharField(max_length=20, choices=[("passed", "Passed"), ("failed", "Failed")], default="passed")
    execution_date = models.DateTimeField(auto_now_add=True)
    remarks = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.test_case.test_title} -> {self.result}"
    

# bug
    
class Bug(models.Model):
    bug_id = models.CharField(max_length=20, unique=True)
    test_case_result = models.ForeignKey(TestCaseResult, on_delete=models.CASCADE, related_name="bugs")
    reported_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="reported_bugs")
    assigned_to = models.ForeignKey(ProjectTeam, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_bugs")
    title = models.CharField(max_length=255)
    description = models.TextField()
    steps_to_reproduce = models.TextField(null=True, blank=True)
    environment = models.CharField(max_length=255, null=True, blank=True)  #e.g., browser, OS, app version)
    priority = models.CharField(max_length=10, choices=TestCasePriority.choices, default=TestCasePriority.MEDIUM)
    severity = models.CharField(max_length=10, choices=[
        ("critical", "Critical"), 
        ("major", "Major"), 
        ("minor", "Minor"), 
        ("trivial", "Trivial")
    ], default="minor")


    status = models.CharField(max_length=20, choices=[("open", "Open"), ("in_progress", "In Progress"), ("resolved", "Resolved")], default="open")
    created_at = models.DateTimeField(auto_now_add=True)
    fix_task = models.ForeignKey("Task", on_delete=models.SET_NULL, null=True, blank=True, related_name="bug_fixes")
    fixed_at = models.DateTimeField(null = True, blank=True)
    FIX_STATUS_CHOICES = [
        ("pending", "Pending"),
        ("in_progress", "In Progress"),
        ("fixed", "Fixed")
    ]
    fix_status = models.CharField(max_length=20, choices=FIX_STATUS_CHOICES, default="pending")
    resolution_notes = models.TextField(null=True, blank=True)

    

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
    
