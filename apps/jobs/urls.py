from django.urls import path

from . import views

urlpatterns = [
    path("", views.job_list, name="job-list"),
    # P2-004: the log view was implemented but never routed. It carries the
    # same target data as jobs (tool commands, hosts, errors), so it is
    # registered with the same membership scoping rather than left unrouted.
    path("logs/", views.log_list, name="job-log-list"),
    path("<int:pk>/", views.job_detail, name="job-detail"),
    path("<int:pk>/cancel/", views.job_cancel, name="job-cancel"),
    path("<int:pk>/retry/", views.job_retry, name="job-retry"),
]
