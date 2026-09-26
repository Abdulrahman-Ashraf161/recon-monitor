from django import forms

from .models import Target


class TargetForm(forms.ModelForm):
    class Meta:
        model = Target
        fields = ["name", "root_domain", "status", "authorization_status",
                  "authorization_expires_at", "auth_warning_days", "scan_profile",
                  "verify_tls", "scan_config"]
        widgets = {"authorization_expires_at": forms.DateTimeInput(attrs={"type": "datetime-local"})}
        help_texts = {
            "scan_config": 'Optional JSON. Example: {"ports": "80,443,8080,8443"}. Leave as {} for defaults.',
            "scan_profile": "Passive=no touch / Balanced=default / Active=ports+content / Full=all.",
            "verify_tls": "Verify TLS certificates (uncheck only for lab targets; shown in logs).",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["scan_config"].required = False

    def clean_scan_config(self):
        val = self.cleaned_data.get("scan_config")
        return val if isinstance(val, dict) else {}
