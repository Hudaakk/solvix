from django.urls import path
from .views import LoginAPIView, ForgotPasswordAPIView, ResetPasswordAPIView, LogoutAPIView, AddUserView, UserListView, DeleteUserView, ChangePasswordView, RoleListView, EditUserView, ProfileView, AddProfilePictureView, ProjectManagerListView, ProjectListView, UserListByRoleView, ProjectArchiveAPIView, ProjectRestoreAPIView, CreateProjectView, LeadProjectListView, ProjectModuleView, ModuleTaskView, ProjectDevelopersView,RoleCreateAPIView, UserprofileView, NotificationListView, DeveloperTaskListView, update_task_status, TrakTaskListView, ProjectCompletedModuleView, MarkNotificationAsRead, TestTypeLisCreateView, TestEngineerView, ModuleTestCaseView, developer_task_statistics, developer_recent_tasks, ProjectDetailView

from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView


urlpatterns = [
    path('login/', LoginAPIView.as_view(), name = 'login'),

    path('token/', TokenObtainPairView.as_view(), name = 'token'),

    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('forgot_password/',ForgotPasswordAPIView.as_view(), name='forgot_password'),

    path('reset-password/', ResetPasswordAPIView.as_view(), name='reset-password'),

    path('logout/', LogoutAPIView.as_view(), name = 'logout'),

    path('add-user/', AddUserView.as_view(), name = 'add-user'),

    path('users_list/', UserListView.as_view(), name = 'users_list'),

    path('delete-user/<int:user_id>/', DeleteUserView.as_view(), name = 'delete_user'),

    path('change_password/', ChangePasswordView.as_view(), name = 'change_password'),
     
    path('roles/add/', RoleCreateAPIView.as_view(), name = 'add_role'),
    
    path('roles/', RoleListView.as_view(), name = 'roles'),

    path('edit_user/<int:user_id>/', EditUserView.as_view(), name = 'edit_user'),
    
    path('profile/<int:user_id>/', UserprofileView.as_view(), name='user-profile-view'), 
    
    path('view_profile/', ProfileView.as_view(), name = 'view_profile'),

    path('add_profile/',AddProfilePictureView.as_view(), name='add_profile'),

    path('project_managers_list/', ProjectManagerListView.as_view(), name = 'project_manager_list'),

    path('project_list/', ProjectListView.as_view(), name = 'project_list'),

    path('project_detail/<int:pk>/', ProjectDetailView.as_view(), name = 'project_detail'),

    path('users_list_by_role/', UserListByRoleView.as_view(), name='users_list_by_role'),

    path("project/<int:pk>/archive/", ProjectArchiveAPIView.as_view(), name = "project-archive"),

    path("project/<int:pk>/restore/", ProjectRestoreAPIView.as_view(), name = 'project-restore'),

    path('projects/create/', CreateProjectView.as_view(), name='create_project'),

    path('lead/projects/', LeadProjectListView.as_view(), name = 'lead_projects'),

    path('projects/<int:project_id>/modules/', ProjectModuleView.as_view(), name='project_module'),

    path('modules/<int:module_id>/tasks/', ModuleTaskView.as_view(), name = 'module-task'),

    path("projects/<int:project_id>/developers/", ProjectDevelopersView.as_view(), name = 'project-developers'),

    path('notifications/', NotificationListView.as_view(), name = "notification-list"),

    path('developer/tasks/', DeveloperTaskListView.as_view(), name = 'developer-task-list'),

    path('developer/tasks/<int:pk>/', DeveloperTaskListView.as_view(), name = 'developer-task-detail'),

    path('developer/tasks/<int:pk>/update-status/', update_task_status, name='update-task-status'),

    path('developer/track_task_list/', TrakTaskListView.as_view(), name='track_task'),
    
    path('projects/<int:project_id>/completed_modules/', ProjectCompletedModuleView.as_view(), name='project-completed_module'),

    path('notifications/<int:notification_id>/mark-as-read/', MarkNotificationAsRead.as_view(), name = 'mark-notification-as-read'),

    path('test_types/', TestTypeLisCreateView.as_view(), name='test-type-list-create'),

    path("projects/<int:project_id>/testEngineers/", TestEngineerView.as_view(), name = 'project-developers'),

    path('modules/<int:module_id>/testcases/', ModuleTestCaseView.as_view(), name='test_case'),

    path('developer/task-status/', developer_task_statistics, name='developer-task'),

    path('developer/recent-tasks/', developer_recent_tasks, name='developer-recent-tasks'),


    


]
