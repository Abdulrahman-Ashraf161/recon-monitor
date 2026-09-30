from django.urls import path

from apps.monitoring import views as export_views

from . import views

urlpatterns = [
    path("", views.target_list, name="target-list"),
    path("add/", views.target_create, name="target-add"),
    path("<int:pk>/", views.target_detail, name="target-detail"),
    path("<int:pk>/edit/", views.target_edit, name="target-edit"),
    path("<int:pk>/pause/", views.target_pause, name="target-pause"),
    path("<int:pk>/resume/", views.target_resume, name="target-resume"),
    path("<int:pk>/delete/", views.target_delete, name="target-delete"),
    path("<int:pk>/scan/", views.target_scan, name="target-scan"),
    # P2-006: the status of a manual scan is exposed through its execution root.
    path("runs/<int:pk>/", views.scan_run_detail, name="scan-run-detail"),
    path("<int:target_id>/exports/", export_views.export_index, name="export-index"),
    path("<int:target_id>/exports/create/", export_views.export_create, name="export-create"),
    path("<int:target_id>/changes/", views.target_changes, name="target-changes"),
]
