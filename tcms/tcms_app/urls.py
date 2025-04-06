from django.urls import path
from .views import *
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

    path('user/update-profile/', UserUpdateView.as_view(), name='user-update'),
    
    path('profile/<int:user_id>/', UserprofileView.as_view(), name='user-profile-view'), 
    
    path('view_profile/', ProfileView.as_view(), name = 'view_profile'),

    path('add_profile/',AddProfilePictureView.as_view(), name='add_profile'),

    path('project_managers_list/', ProjectManagerListView.as_view(), name = 'project_manager_list'),

    path('project_list/', ProjectListView.as_view(), name = 'project_list'),

    path('users_list_by_role/', UserListByRoleView.as_view(), name='users_list_by_role'),

    path("project/<int:pk>/archive/", ProjectArchiveAPIView.as_view(), name = "project-archive"),

    path("project/<int:pk>/restore/", ProjectRestoreAPIView.as_view(), name = 'project-restore'),

    path('projects/create/', CreateProjectView.as_view(), name='create_project'),

    path('projects/<int:project_id>/update/', UpdateProjectView.as_view(), name = 'update-project'),

    path('lead/projects/', LeadProjectListView.as_view(), name = 'lead_projects'),

    path('projects/<int:project_id>/modules/', ProjectModuleView.as_view(), name='project_module'),

    path('modules/<int:module_id>/tasks/', ModuleTaskView.as_view(), name = 'module-task'),

    path('pm/soft-delete-task/<int:pk>/', soft_delete_task, name='soft-delete-task'),

    path("projects/<int:project_id>/developers/", ProjectDevelopersView.as_view(), name = 'project-developers'),

    path('notifications/', NotificationListView.as_view(), name = "notification-list"),

    path('developer/tasks/', DeveloperTaskListView.as_view(), name = 'developer-task-list'),

    path('developer/tasks/<int:pk>/', DeveloperTaskListView.as_view(), name = 'developer-task-detail'),

    path('developer/tasks/<int:pk>/update-status/', update_task_status, name='update-task-status'),

    path('developer/track_task_list/', TrakTaskListView.as_view(), name='track_task'),

    path('qa/projects/', QAProjectListView.as_view(), name = 'qa-projects'),
    
    path('projects/<int:project_id>/completed_modules/', ProjectCompletedModuleView.as_view(), name='project-completed_module'),

    path('notifications/<int:notification_id>/mark-as-read/', MarkNotificationAsRead.as_view(), name = 'mark-notification-as-read'),

    path('test_types/', TestTypeLisCreateView.as_view(), name='test-type-list-create'),

    path("projects/<int:project_id>/testEngineers/", TestEngineerView.as_view(), name = 'project-developers'),

    path('modules/<int:module_id>/testcases/', ModuleTestCaseView.as_view(), name='test_case'),

    path('developer/task-status/', developer_task_statistics, name='developer-task'),

    path('developer/recent-tasks/', developer_recent_tasks, name='developer-recent-tasks'),

    path('developer/upcoming-deadlines/', upcoming_deadlines, name = 'upcoming-deadlines'),

    path('dev/completed-task-list/', completed_developer_tasks, name='dev-cmplt-task'),

    path('dev/pending-task/', pending_developer_tasks, name='dev-pending-task'),

    path('assigned-tests/', AssignedTestCaseListView.as_view(), name='assigned-tests'),

    path('project/details/<int:pk>/', ProjectDetailView.as_view(), name='project-details'),

    path('track-assigned-tests/', TrackAssignedTestCaseListView.as_view(), name='track-assigned-tests'),

    path('test-cases-summary/', TestCaseSummaryView.as_view(), name='test-case-summary'),

    path('test-engineer/recent-activities/', RecentTestEngineerActivities.as_view(), name='recent-test-activities'),

    path('test-engineer/upcoming-due/', TestEngineerUpcomingDueView.as_view(), name = 'test-engineer-upcoming-dues'),

    path('test-cases/<int:pk>/', TestCaseDetailView.as_view(), name = 'test-case-detail'),

    path('test-cases/<int:pk>/update/', TestUpdateView.as_view(), name="test-case-update"),

    path("test-steps/update-status/<int:step_id>/", UpdateTestStepStatus.as_view(), name="update-test-step-status"),

    path('complete-test-case/<int:user_test_case_id>/', CompleteTestCaseResultView.as_view(), name= 'complete-test-case'),

    path('modules/<int:module_id>/failed-test-cases/', FailedTestCaseByModuleView.as_view(), name = 'failed-test-cases-by-module'),

    path('modules/<int:module_id>/passed-test-cases/', PassedTestCaseByModuleView.as_view(), name='passed-test-cases-by-module'),

    path('test-cases/<int:test_case_id>/bugs/', BugsByTestCaseView.as_view(), name = 'bugs-by-test-case'),

    path('bugs/<int:pk>/', BugDetailView.as_view(), name='bug-detail'),

    path('modules/<int:module_id>/developers/', ModuleDeveloperView.as_view(), name='module-developers'),

    path('qa/test-case-stats/', QATestCaseStatsView.as_view(), name='qa-test-case-stats'),

    path('qa/recent-test-cases/', RecentTestCaseActivityView.as_view(), name='recent-test-cases'),

    path('qa/upcoming-test-deadlines/', UpcomingTestCaseDeadlinesView.as_view(), name='qa-upcoming-test-deadlines'),
     
    path('admin/project-stats/', AdminProjectStatsView.as_view(), name='admin-project-stats'),

    path('admin/recent-projects/', RecentProjectsView.as_view(), name='recent-projects'),

    path('admin/user-stats/', UserStatusView.as_view(), name='admin-user-stats'),

    path('admin/user-projects/', UsersWithProjectsListView.as_view(), name='user-projects-list'),#user and its project

    path('tasks/<int:task_id>/comments/', TaskCommentCreateView.as_view(), name='create-task-comment'),

    path('tests/<int:test_id>/comments/', TestCommentCreateView.as_view(), name='create-test-comment'),

    # path('projects/<int:project_id>/team/', ProjectTeamDetailView.as_view(), name='project-team-detail'),

    path('qa-report-bug/<int:test_case_id>/', ReportBugOnTestCaseView.as_view(), name = 'report-bug'),

    path('project-summary/<int:project_id>/', ProjectSummaryView.as_view(), name='project-summary'),

    path('admin/project-detail/<int:project_id>/', AdminProjectDetailView.as_view(), name='project-detail'),

    path('admin/uesrReport/<int:user_id>/', AdminReportUserView.as_view(), name='user-report'),

    path('admin/user-detail/<int:user_id>/', AdminuserDetailView.as_view(), name='admin-user-detail'),

    path('modules/<int:module_id>/bugs/', ModuleBugListView.as_view(), name='module-bug-list'),

    path('pm-projects-graph/', ProjectManagerGraphView.as_view(), name= 'my-projects-graph'),

    path('projects/<int:project_id>/stats/', ProjectStatsView.as_view(), name='project-stats'),

    path('remove-profile-picture/', remove_profile_picture, name='remove-profile-picture'),

    path('pm/bugs/assign-bug/<int:bug_id>/', AssignBugView.as_view(), name='assign-bug'),

    path('dev/tasks-with-bugs/', DeveloperTaskWithBugsView.as_view(), name= 'developer-tasks-with-bugs'),

    path('dev/task-bugs/<int:task_id>/', DeveloperTaskDetailView.as_view(), name='dev-task-details'),

    path('dev/bugs/update/<int:bug_id>/', UpdateBugStatusView.as_view(), name='dev-task-update'),

    path('qa-dashboard-report/',QAReportDashboard.as_view(), name='qa-dashboard-report' ),

    path('qa/failed-testcases/', QaFailedTestcaseWithBugs.as_view(), name='qa-failed-testcase'),


    path('admin/dashboard/user_list_by_exp/', users_by_experience, name='user-list-by-exp'),

    path('PM/<int:project_id>/adduser', AddUsersToProjectView.as_view(), name='add_user_to_existing_project'),

    path('PM/project_with_bugs/', ProjectWithBugsView.as_view(), name='project-with-bugs'),

    path('PM/<int:project_id>/modules_with_bugs/', ModuleWithBugsView.as_view(), name='module-with-bugs'),

    


]
