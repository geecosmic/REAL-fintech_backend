from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from .models import VirtualAccount, UserWallet, ElectricityTransaction
from django.db import transaction
from .serializers import TransactionSerializer  # Make sure this exists
from django.utils.dateparse import parse_date
import requests
import json
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.utils.http import urlsafe_base64_decode

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from .models import UserWallet, Transaction
from .serializers import WalletSerializer
import uuid
from core.models import UserProfile
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate

from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import AllowAny
from django.http import HttpResponse
from django.views import View
import os






from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from decimal import Decimal
import uuid
import requests
from django.conf import settings







class Home(View):
    def get(self, request):
        return HttpResponse('its ok')
    


class EditProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
        })

    def put(self, request):
        user = request.user
        first_name = request.data.get("first_name", "")
        last_name = request.data.get("last_name", "")
        email = request.data.get("email", "")

        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        user.first_name = first_name
        user.last_name = last_name
        user.email = email
        user.save()

        return Response({"message": "Profile updated successfully."})





from core.utils import get_virtual_account_from_provider
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_dashboard(request):
    print("✅ Authenticated User:", request.user)
    user = request.user

    # 🔁 1. FETCH latest virtual account details from provider
    # Example placeholder (replace with real API call)
    account_info = get_virtual_account_from_provider(user)  # <-- you'll define this

    # 🧠 2. Update or create in DB
    VirtualAccount.objects.update_or_create(
        user=user,
        defaults={
            'account_number': account_info['account_number'],
            'bank_name': account_info['bank_name'],
            'provider_ref': account_info['account_reference'],
        }
    )

    # 💰 3. Wallet
    wallet = UserWallet.objects.filter(user=user).first()
    balance = wallet.balance if wallet else 0

    # 📄 4. Recent Transactions
    transactions = Transaction.objects.filter(user=user).order_by('-created_at')[:10]
    txn_data = TransactionSerializer(transactions, many=True).data

    # ✅ 5. Return everything
    return Response({
        "user": user.username,
        "wallet_balance": balance,
        "virtual_account": account_info,
        "recent_transactions": txn_data,
    })








@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    username = request.data.get('username')
    password = request.data.get('password')
    email = request.data.get('email')
    first_name = request.data.get('first_name')
    last_name = request.data.get('last_name')
    pin = request.data.get('pin')  # <-- new

    if not all([username, password, email, first_name, last_name, pin]):
        return Response({'error': 'All fields are required.'}, status=400)
    
    if '@' not in email or '.com' not in email: 
        return Response({'error': 'Please enter a valid email address.'}, status=400)
	

    
    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username already exists'}, status=400)

    user = User.objects.create_user(
        username=username,
        password=password,
        email=email,
        first_name=first_name,
        last_name=last_name
    )

    # ✅ manually create UserProfile and save pin
    UserProfile.objects.create(user=user, pin=pin)

    token, _ = Token.objects.get_or_create(user=user)
    return Response({'token': token.key}, status=201)





  #===============FORGOT PASSWORD=======================

from django.contrib.auth.models import User
from django.utils.crypto import get_random_string
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.conf import settings

class RequestPasswordResetView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')

        try:
            user = User.objects.get(username=username)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            return Response({
                'uid': uid,
                'token': token,
                'username': user.username,
            })
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=404)



        



class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        uidb64 = request.data.get('uid')
        token = request.data.get('token')
        new_password = request.data.get('new_password')

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)

            if not default_token_generator.check_token(user, token):
                return Response({'error': 'Invalid or expired token'}, status=400)

            user.set_password(new_password)
            user.save()

            return Response({'message': 'Password reset successful'}, status=200)

        except (User.DoesNotExist, ValueError, TypeError):
            return Response({'error': 'Invalid user ID'}, status=400)







# from django.core.mail import send_mail
# from django.utils.crypto import get_random_string
# from django.contrib.auth.models import User
# import logging
# from django.contrib import messages

# logger = logging.getLogger(__name__)
#------------------------------WALLET BALANCE--------------------------------------



class WalletBalanceView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user_id = os.getenv('CLUBKONNECT_USERID')
            api_key = os.getenv('CLUBKONNECT_APIKEY')
            url = f"https://www.nellobytesystems.com/APIWalletBalanceV1.asp?UserID={user_id}&APIKey={api_key}"
            response = requests.get(url)
            data = response.json()

            if 'balance' in data:
                return Response({'balance': data['balance']}, status=200)
            else:
                return Response({'error': 'Failed to fetch balance'}, status=400)
        except Exception as e:
            return Response({'error': str(e)}, status=500)
        






# --------------------------------------------------------------------------------------

class CustomLoginView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        token = Token.objects.get(key=response.data['token'])
        user = token.user
        return Response({
            'token': token.key,
            'username': user.username,
            'email': user.email,
        })






# -------------------------FUND WALLET--------------------------------

from decimal import Decimal

class FundWalletView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        amount = request.data.get("amount")
        
        if not amount:
            # Assign a default amount if none is provided
            amount = 100  # Or set this to 0 and let frontend handle real amount during payment
        try:
            amount_decimal = Decimal(str(amount))
        except:
            return Response({"error": "Invalid amount format"}, status=400)


        wallet, _= UserWallet.objects.get_or_create(user=request.user)
        wallet.balance += amount_decimal
        wallet.save()

        Transaction.objects.create(
            user=user,
            amount=amount_decimal,
            txn_type='fund',
            status='success',
            reference=str(uuid.uuid4())
        )

        return Response(WalletSerializer(wallet).data, status=status.HTTP_200_OK)
    



    # ------------------------ VIRTUAL ACCOUNt----------------------------


@api_view(["POST", "GET"])
@permission_classes([IsAuthenticated])
def get_or_create_virtual_account(request):
    user = request.user

    if request.method == "GET":
        # Return already created virtual account if any
        try:
            vaccount = VirtualAccount.objects.get(user=user)
            wallet, _ = UserWallet.objects.get_or_create(user=user)
            return Response({
                "wallet_balance": wallet.balance,
                "account_number": vaccount.account_number,
                "bank_name": vaccount.bank_name,
                "account_reference": vaccount.provider_ref,
            }, status=status.HTTP_200_OK)
        except VirtualAccount.DoesNotExist:
            return Response({"error": "No virtual account found"}, status=404)

    elif request.method == "POST":
        try:
            amount = request.data.get("amount")
            if not amount:
                return Response({"error": "Amount is required"}, status=400)

            try:
                amount_decimal = Decimal(str(amount))
            except:
                return Response({"error": "Invalid amount format"}, status=400)

            tx_ref = f"{user.username}-wallet-{uuid.uuid4()}"

            payload = {
                "email": user.email,
                "is_permanent": False,
                "tx_ref": tx_ref,
                "narration": f"{user.get_full_name()} Wallet Top-up",
                "amount": float(amount_decimal),
                "currency": "NGN",
                "duration": 0
            }

            url = "https://api.flutterwave.com/v3/virtual-account-numbers"
            headers = {
                "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}",
                "Content-Type": "application/json"
            }

            response = requests.post(url, headers=headers, json=payload)
            res_json = response.json()

            if res_json.get("status") != "success":
                return Response({"error": "Failed to create virtual account", "details": res_json}, status=502)

            acct_data = res_json["data"]

            # Ensure wallet exists
            wallet, _ = UserWallet.objects.get_or_create(user=user)

            VirtualAccount.objects.update_or_create(
                user=user,
                defaults={
                    "account_number": acct_data["account_number"],
                    "bank_name": acct_data["bank_name"],
                    "provider_ref": acct_data["order_ref"],
                    "tx_ref": tx_ref,
                }
            )

            return Response({
                "wallet_balance": wallet.balance,
                "account_number": acct_data["account_number"],
                "bank_name": acct_data["bank_name"],
                "account_reference": acct_data["order_ref"],
            }, status=201)

        except Exception as e:
            return Response({"error": str(e)}, status=500)







from django.core.mail import send_mail
from django.conf import settings

@api_view(["POST"])
@permission_classes([AllowAny])
def withdraw_funds(request):
    data = request.data
    bank = data.get('bank_name')
    name = data.get('account_name')
    number = data.get('account_number')
    email = data.get('email')

    if not all([bank, name, number, email]):
        return Response({"error": "All fields required"}, status=400)

    message = f"""
New Withdrawal Request:

Bank Name: {bank}
Account Name: {name}
Account Number: {number}
User Email: {email}
"""

    try:
        send_mail(
            'New Withdrawal Request',
            message,
            settings.DEFAULT_FROM_EMAIL,
            ['alephgeeeenterprise@gmail.com'],
            fail_silently=False,
        )
    except Exception as e:
        return Response({"error": str(e)}, status=500)

    return Response({"message": "Email sent"})







# -----------------------------TRANSACTION HISTORY--------------------------------------


class TransactionHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        transactions = Transaction.objects.filter(user=request.user)

        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')

        if start_date:
            transactions = transactions.filter(created_at__date__gte=parse_date(start_date))
        if end_date:
            transactions = transactions.filter(created_at__date__lte=parse_date(end_date))

        transactions = transactions.order_by('-created_at')
        return Response(TransactionSerializer(transactions, many=True).data)
    


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def clear_transactions(request):
    Transaction.objects.filter(user=request.user).delete()
    return Response(status=204)


    # ------------------------- WEBHOOK------------------------------------


import logging
logger = logging.getLogger(__name__)



@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def flutterwave_webhook(request):
    # logger.warning("🔥 Webhook HIT")
    # logger.warning("Headers: %s", request.headers)
    # logger.warning("Payload: %s", request.data)

    signature = request.headers.get('verif-hash')
    if not signature or signature != settings.FLUTTERWAVE_SECRET_HASH:
        logger.error("❌ Invalid webhook signature.")
        return Response({"error": "Invalid signature"}, status=403)

    payload = request.data
    event = payload.get('event')
    data = payload.get('data', {})

    if event in ['charge.completed', 'transfer.completed'] and data.get("status", "").lower() == "successful":
        tx_ref = data.get("tx_ref")
        reference = data.get("flw_ref") or data.get("reference")
        amount = Decimal(str(data.get("amount", 0)))
        customer_email = data.get("customer", {}).get("email")

        logger.warning("✅ Processing transaction: %s | amount: %s", tx_ref, amount)

        if not tx_ref or not customer_email:
            logger.error("❌ Missing tx_ref or customer_email")
            return Response({"error": "Missing tx_ref or customer_email"}, status=400)

        # Check if this transaction was already processed
        if Transaction.objects.filter(reference=reference, status='success').exists():
            logger.warning("⚠️ Transaction already processed: %s", reference)
            return Response({"message": "Already processed"})

        # Try to fetch the user
        user = User.objects.filter(email=customer_email).first()
        if not user:
            logger.error("❌ No user found with email: %s", customer_email)
            return Response({"error": "User not found"}, status=404)

        # Try to get an existing transaction with that tx_ref
        tx = Transaction.objects.filter(tx_ref=tx_ref).first()

        if tx:
            logger.info("🔁 Found existing transaction. Updating...")
            tx.status = 'success'
            tx.reference = reference
            tx.meta = payload
        else:
            logger.info("🆕 Creating new transaction record")
            tx = Transaction(
                user=user,
                txn_type='fund',
                tx_ref=tx_ref,
                reference=reference,
                amount=amount,
                status='success',
                meta=payload
            )

        tx.save()

        # Credit user's wallet
        try:
            wallet, _ = UserWallet.objects.get_or_create(user=user)
            wallet.balance += amount
            wallet.save()

            logger.info("💰 Wallet funded for user: %s", user.email)
            return Response({"message": "Wallet funded"}, status=200)

        except Exception as e:
            logger.error("💥 Error updating wallet: %s", str(e))
            return Response({"error": "Failed to update wallet"}, status=500)

    return Response({"message": "Event ignored"}, status=200)
    




def get_user_from_tx_ref(tx_ref):
    try:
        account = VirtualAccount.objects.get(tx_ref=tx_ref)
        return account.user
    except VirtualAccount.DoesNotExist:
        return None










# ----------------------------------AIRTIME VIEW-----------------------


from .models import UserWallet, Transaction
# this 0ne

class AirtimePurchaseView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print("Incoming POST:", request.data)

        amount = request.data.get('amount')
        phone = request.data.get('phone')
        network = request.data.get('network')
        user = request.user

        if not all([amount, phone, network]):
            return Response({"error": "All fields are required."}, status=400)

        try:
            amount = int(amount)
        except ValueError:
            return Response({"error": "Invalid amount format. Use whole numbers only."}, status=400)

        original_amount = amount  # amount user wants as airtime
        adjusted_amount = original_amount  # amount to deduct from wallet

        if not user.is_staff:
            # Apply discount (user gets a bonus)
            if network == "01":  # MTN
                adjusted_amount = original_amount - int(0.02 * original_amount)
            elif network == "04":  # 9mobile
                adjusted_amount = original_amount - int(0.03 * original_amount)
            elif network == "02":  # Glo
                adjusted_amount = original_amount - int(0.03 * original_amount)
            elif network == "03":  # Airtel
                adjusted_amount = original_amount - int(0.02 * original_amount)

        try:
            wallet = UserWallet.objects.get(user=user)
        except UserWallet.DoesNotExist:
            return Response({"error": "Wallet not found."}, status=404)

        if wallet.balance < Decimal(adjusted_amount):
            return Response({"error": "Insufficient wallet balance."}, status=400)

        request_id = str(uuid.uuid4())
        clubkonnect_url = "https://www.nellobytesystems.com/APIAirtimeV1.asp"
        params = {
            "UserID": settings.CLUBKONNECT_USERID,
            "APIKey": settings.CLUBKONNECT_APIKEY,
            "MobileNetwork": network,
            "Amount": str(original_amount),
            "MobileNumber": phone,
            "RequestID": request_id,

            # "CallBackURL": "https://yourdomain.com/webhook/"
            "CallBackURL":settings.CLUBKONNECT_CALLBACK

        }




        # Wrap in a DB transaction to ensure rollback if something fails
        with transaction.atomic():
            wallet.balance -= Decimal(adjusted_amount)
            wallet.save()
            # print("✅ Deducted from wallet. New balance:", wallet.balance)

            try:
                response = requests.get(clubkonnect_url, params=params, timeout=10)
                result = response.json()

                api_status = result.get("Status") or result.get("status")
                if api_status and api_status.lower() in ["successful", "order_received"]:
                    final_status = "success"
                else:
                    raise Exception("API responded with failure")

            except Exception as e:
                wallet.balance += Decimal(adjusted_amount)
                wallet.save()
                print("❌ Error or failed response. Refunded:", adjusted_amount)
                res_data = response.json()

                Transaction.objects.create(
                    user=user,
                    txn_type='airtime',
                    amount=Decimal(adjusted_amount),
                    status="failed",
                    reference=request_id,
                    # meta={"error": str(e)}
                    meta=res_data 
                )
                return Response({"error": f"Airtime request failed: {str(e)}"}, status=500)

            # Log successful transaction
            Transaction.objects.create(
                user=user,
                txn_type='airtime',
                amount=Decimal(adjusted_amount),
                status="success",
                reference=request_id,
                meta=result
            )

        return Response({
            "message": "Airtime request sent successfully.",
            "status": "success",
            "api_response": result,

            "new_balance": str(wallet.balance) 
        }, status=200) 

              

    







    # -----------------------DATA VIEW --------------------------------



class DataPurchaseView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        phone = request.data.get('phone')
        network = request.data.get('network')      # E.g., "01", "02", "03", "04"
        data_plan = request.data.get('data_plan')  # E.g., "1000.0"
        base_amount = request.data.get('amount')   # Sent from frontend

        user = request.user

        if not all([base_amount, phone, network, data_plan]):
            return Response({"error": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            real_amount = Decimal(str(base_amount))
        except Exception:
            return Response({"error": "Invalid amount."}, status=status.HTTP_400_BAD_REQUEST)

        # Apply markup for non-staff users
        adjusted_amount = real_amount
        if not user.is_staff:
            if network == "01":       # MTN
                adjusted_amount += real_amount * Decimal("0.02") #2%
            elif network == "03":     # Airtel
                adjusted_amount += real_amount * Decimal("0.03") #3%
            elif network == "02":     # Glo
                adjusted_amount += real_amount * Decimal("0.035") #3.5%
            elif network == "04":     # 9mobile
                adjusted_amount += real_amount * Decimal("0.055") #5.5%

        adjusted_amount = adjusted_amount.quantize(Decimal("1."))  # Round to whole naira

        # Get wallet
        try:
            wallet = UserWallet.objects.get(user=user)
        except UserWallet.DoesNotExist:
            return Response({"error": "Wallet not found."}, status=status.HTTP_404_NOT_FOUND)

        if wallet.balance < adjusted_amount:
            return Response({"error": "Insufficient wallet balance."}, status=status.HTTP_400_BAD_REQUEST)

        # Deduct wallet balance
        wallet.balance -= adjusted_amount
        wallet.save()

        # Generate unique transaction ID
        request_id = str(uuid.uuid4())[:10]

        # Call ClubKonnect
        url = (
            f"{settings.CLUBKONNECT_DATA_URL}"
            f"?UserID={settings.CLUBKONNECT_USERID}"
            f"&APIKey={settings.CLUBKONNECT_APIKEY}"
            f"&MobileNetwork={network}"
            f"&DataPlan={data_plan}"
            f"&MobileNumber={phone}"
            f"&RequestID={request_id}"
            f"&CallBackURL={settings.CLUBKONNECT_CALLBACK}"
        )

        try:
            response = requests.get(url)
            result = response.json()
        except Exception as e:
            # Refund wallet on failure
            wallet.balance += adjusted_amount
            wallet.save()
            return Response({"error": "Failed to contact data provider."}, status=status.HTTP_502_BAD_GATEWAY)

        # Log transaction
        Transaction.objects.create(
            user=user,
            txn_type='data',
            amount=adjusted_amount,
            status=result.get("orderstatus", "pending").lower(),
            reference=request_id,
            # meta=result
            meta={"raw_response": response.text}
        )

        return Response({
            "message": "✅ Data purchase initiated.",
            "order_status": result.get("status"),
            "real_amount": str(real_amount),
            "adjusted_amount": str(adjusted_amount),
            "phone": phone,
            "network": network,
            "data_plan": data_plan,
            "transaction_id": request_id,
            "api_response": result
        }, status=status.HTTP_200_OK)








from decimal import Decimal, ROUND_HALF_UP

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_data_plans(request):
    from decimal import Decimal, ROUND_HALF_UP

    network = request.GET.get("network")

    if not network:
        return JsonResponse({"error": "Network parameter is required."}, status=400)

    # ✅ Use exact ClubKonnect values: 'MTN', 'Glo', 'm_9mobile', 'Airtel'
    clubkonnect_values = ['MTN', 'Glo', 'm_9mobile', 'Airtel']

    # Match exact label, ignoring case
    matched_value = next((val for val in clubkonnect_values if val.lower() == network.lower()), None)

    if not matched_value:
        return JsonResponse({"error": f"Unsupported network: {network}"}, status=400)

    url = (
        f"{settings.CLUBKONNECT_DATA_PLAN_LIST_URL}"
        f"?UserID={settings.CLUBKONNECT_USERID}"
        f"&APIKey={settings.CLUBKONNECT_APIKEY}"
        f"&MobileNetwork={matched_value}"
    )

    try:
        
        response = requests.get(url)
        data = response.json()

        
        

        mobile_networks = data.get("MOBILE_NETWORK", {})
        network_data_list = mobile_networks.get(matched_value)

        if not network_data_list or not isinstance(network_data_list, list):
            return JsonResponse({"error": f"No data list found for {matched_value}", "raw": data}, status=502)

        products = network_data_list[0].get("PRODUCT", [])
        if not products:
            return JsonResponse({"error": f"No products found for {matched_value}", "raw": data}, status=502)

        output = []
        for item in products:
            output.append({
                "code": item.get("PRODUCT_ID"),
                "name": item.get("PRODUCT_NAME"),
                "price": int(Decimal(item.get("PRODUCT_AMOUNT", "0")).quantize(Decimal("1"), rounding=ROUND_HALF_UP)),
            })

        return JsonResponse(output, safe=False)

    except Exception as e:
        return JsonResponse({"error": "Failed to fetch plans", "detail": str(e)}, status=500)




# ---------------------------CABLE VIEW -------------------------------


class CableTVPurchaseView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        provider = request.GET.get("provider")
        if not provider:
            return Response({"error": "Provider is required."}, status=status.HTTP_400_BAD_REQUEST)

        packages = CablePackage.objects.filter(provider=provider.lower())
        if not packages.exists():
            return Response({"error": "No packages found for this provider."}, status=status.HTTP_404_NOT_FOUND)

        data = [
            {"code": pkg.code, "name": pkg.name, "amount": int(pkg.amount)}
            for pkg in packages
        ]
        return Response(data, status=status.HTTP_200_OK)
    
    def post(self, request):
        smartcard = request.data.get("smartcard")
        phone = request.data.get("phone")
        cabletv = request.data.get("cabletv")  # e.g., dstv, gotv
        package = request.data.get("package")  # e.g., dstv-yanga
        amount = request.data.get("amount")    # must match the selected package

        if not all([smartcard, phone, cabletv, package, amount]):
            return Response({"error": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            amount = Decimal(amount)
        except:
            return Response({"error": "Invalid amount."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            wallet = UserWallet.objects.get(user=request.user)
        except UserWallet.DoesNotExist:
            return Response({"error": "Wallet not found."}, status=status.HTTP_404_NOT_FOUND)

        if wallet.balance < amount:
            return Response({"error": "Insufficient wallet balance."}, status=status.HTTP_400_BAD_REQUEST)

        request_id = str(uuid.uuid4())
        callback_url = "https://192.168.0.199:8000/callback"

        api_url = (
            f"{settings.CLUBKONNECT_CABLE_URL}?UserID={settings.CLUBKONNECT_USERID}"
            f"&APIKey={settings.CLUBKONNECT_APIKEY}"
            f"&CableTV={cabletv}&Package={package}&SmartCardNo={smartcard}"
            f"&PhoneNo={phone}&RequestID={request_id}&CallBackURL={callback_url}"
        )

        try:
            response = requests.get(api_url)
            data = response.json()
            print("CLUBKONNECT SUBSCRIBE RESPONSE:", data) 
        except Exception as e:
            return Response({"error": "Failed to contact provider."}, status=status.HTTP_502_BAD_GATEWAY)

        if data.get("statuscode") == "100":
            wallet.balance -= amount
            wallet.save()

            Transaction.objects.create(
                user=request.user,
                txn_type='cable',
                amount=amount,
                status='success',
                reference=data.get("orderid", request_id),
                meta={
                    "package": package,
                    "smartcard": smartcard,
                    "phone": phone,
                    "provider": cabletv,
                    "response": response.text
                }
            )

            return Response({
                "message": "Cable TV subscription successful.",
                "order_id": data.get("orderid"),
                "status": data.get("status"),
                "amount": str(amount)
            })

        return Response({
            "error": "Subscription failed.",
            "details": data
        }, status=status.HTTP_400_BAD_REQUEST)









from django.http import JsonResponse
from .models import CablePackage

def cable_packages(request):
    provider = request.GET.get('provider')
    packages = CablePackage.objects.filter(provider=provider)

    data = [
        {"code": pkg.code, "name": pkg.name, "amount": pkg.amount}
        for pkg in packages
    ]
    return JsonResponse(data, safe=False)


from .models import SmartcardHistory

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def verify_smartcard(request):
    provider = request.GET.get("provider")  # dstv, gotv, startimes
    smartcard = request.GET.get("smartcard")

    print("DEBUG‑USERID:", settings.CLUBKONNECT_USERID)
    print("DEBUG‑APIKEY:", settings.CLUBKONNECT_APIKEY)

    if not provider or not smartcard:
        return Response({"error": "Missing provider or smartcard"}, status=400)

    url = (
        f"{settings.CLUBKONNECT_VERIFY_URL}?"
        f"UserID={settings.CLUBKONNECT_USERID}"
        f"&APIKey={settings.CLUBKONNECT_APIKEY}"
        f"&CableTV={provider}&SmartCardNo={smartcard}"

        
    )
    

    try:
        res = requests.get(url, timeout=15)
        

        data = res.json()
    except Exception:
        return Response({"error": "Unable to connect to Clubkonnect"}, status=502)

    if data.get("status") == "00":
        SmartcardHistory.objects.update_or_create(
        user=request.user,
        provider=provider,
        smartcard=smartcard,
        defaults={"customer_name": data.get("customer_name", "")}
        )
        return Response({
            "statuscode": "100",
            "name": data.get("customer_name"),
            "raw": data
        })
    else:
        return Response({
            "statuscode": "101",
            "error": data.get("status") or "Verification failed",
            "raw": data
        }, status=400)
        

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_saved_smartcards(request):
    provider = request.GET.get("provider")
    if not provider:
        return Response({"error": "Provider required"}, status=400)

    cards = SmartcardHistory.objects.filter(user=request.user, provider=provider).order_by("-last_used")[:3]
    data = [{"smartcard": c.smartcard, "name": c.customer_name} for c in cards]
    return Response(data)



    # -----------------------ELECTRICITY--------------------




# @csrf_exempt
# @login_required

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated







@api_view(['POST'])
@permission_classes([IsAuthenticated])
def buy_electricity(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    user = request.user
    data = request.data

    disco = data.get('disco')
    meter_no = data.get('meter_no')
    meter_type = data.get('meter_type')
    phone = data.get('phone')
    amount_str = data.get('amount')

    if not all([disco, meter_no, meter_type, phone, amount_str]):
        return JsonResponse({'error': 'All fields are required'}, status=400)

    try:
        amount = Decimal(amount_str)
    except:
        return JsonResponse({'error': 'Invalid amount format'}, status=400)

    try:
        wallet = UserWallet.objects.get(user=user)
        if wallet.balance < amount:
            return JsonResponse({'error': 'Insufficient wallet balance.'}, status=400)
    except UserWallet.DoesNotExist:
        return JsonResponse({'error': 'Wallet not found.'}, status=404)

    request_id = str(uuid.uuid4())

    payload = {
        "UserID": settings.CLUBKONNECT_USERID,
        "APIKey": settings.CLUBKONNECT_APIKEY,
        "ElectricCompany": disco,
        "MeterType": meter_type,
        "MeterNo": meter_no,
        "Amount": str(amount),
        "PhoneNo": phone,
        "RequestID": request_id,
        "CallBackURL": settings.CLUBKONNECT_CALLBACK,
    }

    try:
        response = requests.post(settings.CLUBKONNECT_ELECTRICITY_URL, data=payload, timeout=15)
        print("ClubKonnect Raw Response:", response.text)

        if not response.text:
            return JsonResponse({'error': 'Empty response from provider'}, status=502)

        res_data = response.json()

    except ValueError as e:
        print("JSON decode error:", e)
        Transaction.objects.create(
            user=user,
            txn_type='electricity',
            amount=amount,
            status='failed',
            reference=request_id,
            meta={'error': 'Invalid JSON', 'response': response.text},
            response_log=response.text
        )
        return JsonResponse({'error': 'Invalid response format from provider'}, status=502)

    except Exception as e:
        print("Connection error:", e)
        Transaction.objects.create(
            user=user,
            txn_type='electricity',
            amount=amount,
            status='failed',
            reference=request_id,
            meta={'error': str(e)},
            response_log=str(e)
        )
        return JsonResponse({'error': 'Electricity purchase failed', 'detail': str(e)}, status=502)

    # Parse provider response
    status_code = str(res_data.get("status") or res_data.get("Status", "")).lower()
    message = res_data.get("message") or res_data.get("Message", "No message provided")
    metertoken = res_data.get("metertoken", "")

    if status_code in ["successful", "success", "completed"]:
        txn_status = "success"
    elif status_code in ["order_received", "pending"]:
        txn_status = "pending"
    else:
        txn_status = "failed"

    # Only deduct if transaction is fully successful
    if txn_status == "success":
        wallet.balance -= amount
        wallet.save()

    txn = Transaction.objects.create(
        user=user,
        txn_type='electricity',
        amount=amount,
        reference=request_id,
        status=txn_status,
        meta={**res_data, "metertoken": metertoken},
        response_log=json.dumps(res_data)
    )

    if txn_status == 'success':
        return JsonResponse({'message': 'Electricity purchase successful', 'data': res_data}, status=200)
    elif txn_status == 'pending':
        return JsonResponse({'message': 'Order received. Awaiting confirmation from provider.', 'data': res_data}, status=202)
    else:
        return JsonResponse({'error': 'Purchase failed', 'message': message, 'response': res_data}, status=400)








from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.conf import settings
import requests
import json

# @csrf_exempt
# @login_required

@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_meter_number(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

    data = json.loads(request.body)
    meter_no = data.get("meter_no")
    disco = data.get("disco")

    if not meter_no or not disco:
        return JsonResponse({'error': 'Both meter_no and disco are required.'}, status=400)

    verify_url = (
    f"{settings.CLUBKONNECT_ELECTRICITY_VERIFY_URL}"
    f"?UserID={settings.CLUBKONNECT_USERID}"
    f"&APIKey={settings.CLUBKONNECT_APIKEY}"
    f"&ElectricCompany={disco}"
    f"&meterno={meter_no}"
)


    try:
        response = requests.get(verify_url, timeout=10)
        data = response.json()

        if "customer_name" in data and "INVALID" not in data["customer_name"]:
            return JsonResponse({'customer_name': data["customer_name"]})
        else:
            return JsonResponse({'error': 'Invalid meter number'}, status=400)

    except Exception as e:
        return JsonResponse({'error': 'Verification failed', 'detail': str(e)}, status=500)


# views.py
# views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_electricity_providers(request):
    providers = [
        {"name": "Eko Electric - EKEDC", "code": "01"},
        {"name": "Ikeja Electric - IKEDC", "code": "02"},
        {"name": "Abuja Electric - AEDC", "code": "03"},
        {"name": "Kano Electric - KEDCO", "code": "04"},
        {"name": "Port Harcourt Electric - PHEDC", "code": "05"},
        {"name": "Jos Electric - JEDC", "code": "06"},
        {"name": "Ibadan Electric - IBEDC", "code": "07"},
        {"name": "Kaduna Electric - KAEDC", "code": "08"},
        {"name": "Enugu Electric - EEDC", "code": "09"},
        {"name": "Benin Electric - BEDC", "code": "10"},
        {"name": "Yola Electric - YEDC", "code": "11"},
        {"name": "Aba Electric - APLE", "code": "12"},
    ]
    return Response(providers)





@csrf_exempt
def electricity_callback(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    try:
        data = json.loads(request.body.decode('utf-8'))

        txn_id = data.get('transactionid')
        status = data.get('status', '').lower()
        metertoken = data.get('metertoken', '')
        meter_no = data.get('meterno', '')
        request_id = data.get('requestid')

        if not txn_id:
            return JsonResponse({'error': 'Missing transaction ID'}, status=400)

        # ✅ Update generic Transaction
        txn = Transaction.objects.filter(meta__transactionid=txn_id).first()
        if txn:
            txn.meta['callback'] = data  # store entire callback
            txn.meta['metertoken'] = metertoken
            txn.status = 'success' if status in ['success', 'successful'] else status
            txn.save()

        # ✅ Update ElectricityTransaction if it exists
        if request_id:
            elec_txn = ElectricityTransaction.objects.filter(request_id=request_id).first()
            if elec_txn:
                elec_txn.token = metertoken
                elec_txn.status = 'success' if status in ['success', 'successful'] else status
                elec_txn.response_log = json.dumps(data)
                elec_txn.save()

        return JsonResponse({'message': 'Callback processed'})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)






# # --------------WITHDRAWAL VIEW ------------------------

class WithdrawFundsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        amount = request.data.get('amount')
        bank_name = request.data.get('bank_name')
        account_number = request.data.get('account_number')
        account_name = request.data.get('account_name')

        if not all([amount, bank_name, account_number, account_name]):
            return Response({"error": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            amount = Decimal(amount)
        except:
            return Response({"error": "Invalid amount."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            wallet = UserWallet.objects.get(user=request.user)
        except UserWallet.DoesNotExist:
            return Response({"error": "Wallet not found."}, status=status.HTTP_404_NOT_FOUND)

        if wallet.balance < amount:
            return Response({"error": "Insufficient balance."}, status=status.HTTP_400_BAD_REQUEST)

        # Simulate withdrawal by reducing wallet balance
        wallet.balance -= amount
        wallet.save()

        Transaction.objects.create(
            user=request.user,
            txn_type='withdraw',
            amount=amount,
            status='success',
            reference=str(uuid.uuid4())
        )

        return Response({
            "message": "Withdrawal successful (simulated).",
            "amount": str(amount),
            "bank_name": bank_name,
            "account_number": account_number,
            "account_name": account_name
        }, status=status.HTTP_200_OK)



