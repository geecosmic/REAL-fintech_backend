
import requests
import uuid
from django.conf import settings

def get_virtual_account_from_provider(user):
    url = "https://api.flutterwave.com/v3/virtual-account-numbers"
    headers = {
        "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    tx_ref = f"{user.username}-wallet-{uuid.uuid4()}"

    payload = {
        "email": user.email,
        "is_permanent": False,
        "tx_ref": tx_ref,
        "narration": f"{user.get_full_name()} Wallet Top-up",
        "amount": 100,
        "currency": "NGN",
        "duration": 0
    }

    response = requests.post(url, headers=headers, json=payload)
    res_json = response.json()

    if res_json.get("status") != "success":
        raise Exception(f"Failed to create virtual account: {res_json}")

    acct_data = res_json["data"]
    return {
        "account_number": acct_data["account_number"],
        "bank_name": acct_data["bank_name"],
        "account_reference": acct_data["order_ref"],
        "tx_ref": tx_ref
    }




def send_elastic_email(to_email, subject, body_html):
    api_key = os.getenv("ELASTIC_EMAIL_API_KEY")
    from_email = os.getenv("DEFAULT_FROM_EMAIL", "alephgeeenterprise@gmail.com")

    payload = {
        "apikey": api_key,
        "from": from_email,
        "to": to_email,
        "subject": subject,
        "bodyHtml": body_html,
        "isTransactional": True
    }

    response = requests.post("https://api.elasticemail.com/v2/email/send", data=payload)
    return response.status_code, response.text
