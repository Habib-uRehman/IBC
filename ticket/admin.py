# Add this to your admin.py file

from django.contrib import admin
from .models import TicketUser, Ticket, ScanLog, Operator, TicketQuota

@admin.register(Operator)
class OperatorAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'location', 'contact_number', 'is_active', 'count_registered_users', 'count_generated_tickets')
    list_filter = ('is_active', 'location')
    search_fields = ('name', 'user__username', 'location', 'contact_number')
    readonly_fields = ('created_at',)
    
    def get_readonly_fields(self, request, obj=None):
        # Make user field read-only after creation
        if obj:  # editing an existing object
            return self.readonly_fields + ('user',)
        return self.readonly_fields

@admin.register(TicketQuota)
class TicketQuotaAdmin(admin.ModelAdmin):
    list_display = ('ticket_type', 'total_quantity', 'sold_quantity', 'remaining')
    readonly_fields = ('sold_quantity',)
    
    def remaining(self, obj):
        return obj.remaining

# Your existing model registrations
@admin.register(TicketUser)
class TicketUserAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'cnic_number', 'email', 'gender', 'registered_by', 'created_at')
    list_filter = ('gender', 'relationship', 'registered_by')
    search_fields = ('full_name', 'father_name', 'cnic_number', 'email', 'phone_number')
    readonly_fields = ('user_id', 'created_at', 'updated_at')

@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ('ticket_id', 'get_user_name', 'ticket_type', 'price', 'status', 'created_at')
    list_filter = ('ticket_type', 'status', 'is_tampered')
    search_fields = ('ticket_id', 'user__full_name', 'user__cnic_number')
    readonly_fields = ('ticket_id', 'created_at', 'updated_at')
    
    def get_user_name(self, obj):
        return obj.user.full_name
    get_user_name.short_description = 'User Name'

@admin.register(ScanLog)
class ScanLogAdmin(admin.ModelAdmin):
    list_display = ('log_id', 'get_ticket_id', 'get_user_name', 'gate', 'scanned_at', 'scanned_by')
    list_filter = ('gate', 'scanned_at')
    search_fields = ('ticket__ticket_id', 'ticket__user__full_name')
    readonly_fields = ('log_id', 'scanned_at')
    
    def get_ticket_id(self, obj):
        return obj.ticket.ticket_id
    get_ticket_id.short_description = 'Ticket ID'
    
    def get_user_name(self, obj):
        return obj.ticket.user.full_name
    get_user_name.short_description = 'User Name'