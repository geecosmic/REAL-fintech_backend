

import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "fintech_backend.settings")
django.setup()

from django.core.mail import send_mail
from django.conf import settings

print("Sending email...")

send_mail(
    subject="✅ Test Email via Brevo SMTP",
    message="This is a successful test email from your Django app via Brevo SMTP.",
    from_email=settings.DEFAULT_FROM_EMAIL,
    recipient_list=["eyogeorge23@gmail.com"],
    fail_silently=False,
)

print("✅ Email sent successfully (if no error above).")
