from django.contrib import admin
from .models import UserWallet

@admin.register(UserWallet)
class UserWalletAdmin(admin.ModelAdmin):
    list_display = ('user', 'balance')
    search_fields = ('user__username',)





from .models import Transaction

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ['user', 'txn_type', 'amount', 'status', 'reference', 'created_at']
    list_filter = ['txn_type', 'status', 'created_at']
    search_fields = ['reference', 'meta']



# @admin.register(DataPlan)
# class DataPlanAdmin(admin.ModelAdmin):
#     list_display = ('network', 'name', 'code', 'price')
#     search_fields = ('network', 'name', 'code')
#     list_filter = ('network',)


from .models import CablePackage

@admin.register(CablePackage)
class CablePackageAdmin(admin.ModelAdmin):
    list_display = ('provider', 'name', 'code', 'amount')
    list_filter = ('provider',)
    search_fields = ('name', 'code')



from django.contrib import admin
from .models import ElectricityTransaction

@admin.register(ElectricityTransaction)
class ElectricityTransactionAdmin(admin.ModelAdmin):
    list_display = ['user', 'meter_no', 'amount', 'status', 'created_at']
    search_fields = ['meter_no', 'token', 'request_id', 'order_id']
    list_filter = ['status', 'disco', 'created_at']
