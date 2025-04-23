from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.contrib import messages
from django.core.paginator import Paginator
from django.views.decorators.http import require_POST
from django.utils import timezone
from django.urls import reverse
from django.core.exceptions import ValidationError
from django.conf import settings
import uuid
from django.db.models import Count, Sum, F, Case, When, IntegerField, DecimalField, Value, CharField
from django.db.models.functions import TruncDate, Concat

from django.utils import timezone

"""Export financial report to Excel"""
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required, user_passes_test
import pandas as pd
import io
from datetime import datetime

import csv
import json
import logging

from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import TicketUser, Ticket, ScanLog, Operator, TicketQuota
from .forms import TicketUserForm, TicketForm, ScanTicketForm, TicketSearchForm, ReportForm, QuotaForm
from .utils import generate_qr_code, process_ticket_scan, get_dashboard_stats, export_tickets_to_csv

# Set up logging
logger = logging.getLogger(__name__)

from django.contrib.auth import logout
from django.shortcuts import redirect
from django.contrib.auth.models import User

def is_operator(user):
    """Check if user is an operator"""
    return hasattr(user, 'operator_profile')

def is_admin(user):
    """Check if user is an admin"""
    return user.is_staff or user.is_superuser



def logout_view(request):
    """Handle logout and redirect to login page"""
    logout(request)
    return redirect('login')

def login_view(request):
    """Handle login and redirect to appropriate dashboard"""
    # If user is already authenticated, redirect to appropriate dashboard
    if request.user.is_authenticated:
        if is_admin(request.user):
            return redirect('admin_dashboard')
        elif is_operator(request.user):
            return redirect('operator_dashboard')
        else:
            return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            
            # Redirect based on user type
            if is_admin(user):
                return redirect('admin_dashboard')
            elif is_operator(user):
                return redirect('operator_dashboard')
            else:
                return redirect('dashboard')  # Regular user dashboard
        else:
            messages.error(request, "Invalid username or password.")
    
    return render(request, 'login.html')


@login_required
def dashboard(request):
    """Display the main dashboard with statistics"""
    stats = get_dashboard_stats()
    return render(request, 'dashboard.html', {'stats': stats})


# Add this at the top of your views.py file
import logging
logger = logging.getLogger(__name__)

@login_required
def register_user(request):
    """Register a new user"""
    if request.method == 'POST':
        try:
            # Extract data from POST request
            full_name = request.POST.get('full_name')
            father_name = request.POST.get('father_name')
            email = request.POST.get('email')
            phone_number = request.POST.get('phone_number')
            cnic_number = request.POST.get('cnic_number')
            relationship = request.POST.get('relationship', 'self')
            related_to = request.POST.get('related_to', '')
            gender = request.POST.get('gender')
            age = request.POST.get('age')

            logger.info("Processing register_user POST request")
            logger.info(f"POST data: {request.POST}")
            logger.info(f"FILES data: {request.FILES}")
            logger.info(f"Content type: {request.content_type}")

            relationship = request.POST.get('relationship', 'self')
            related_to = request.POST.get('related_to', '')
            
            # Get the operator from the request user
            operator = None
            if hasattr(request.user, 'operator_profile'):
                operator = request.user.operator_profile
            
            # Create new user with transaction to ensure atomicity
            with transaction.atomic():
                user = TicketUser(
                    # Existing fields...
                    relationship=relationship,
                    related_to=related_to if relationship != 'self' else None,
                    registered_by=operator
                )
            
            # Check if the form has the correct enctype
            if not request.content_type.startswith('multipart/form-data'):
                logger.warning("Form does not have multipart/form-data enctype!")
            
            # Check files
            if 'profile_picture' in request.FILES:
                file = request.FILES['profile_picture']
                logger.info(f"Profile picture provided: {file.name}, size: {file.size}, type: {file.content_type}")
            else:
                logger.info("No profile picture provided")
            
            # Validate required fields
            if not all([full_name, email, phone_number, cnic_number, gender]):
                messages.error(request, "Please fill all required fields.")
                return render(request, 'user_register.html')
            
            # Only check for CNIC uniqueness if this is a primary user (relationship = 'self')
            if relationship == 'self':
                # Check if another primary user has this CNIC
                if TicketUser.objects.filter(cnic_number=cnic_number, relationship='self').exists():
                    messages.error(request, "This CNIC is already registered as a primary user.")
                    return render(request, 'user_register.html')
            elif not related_to:
                # If not self, related_to should be provided
                messages.error(request, "Please specify who this person is related to.")
                return render(request, 'user_register.html')
            
            # Create new user with transaction to ensure atomicity
            with transaction.atomic():
                user = TicketUser(
                    full_name=full_name,
                    father_name=father_name,
                    email=email,
                    phone_number=phone_number,
                    cnic_number=cnic_number,
                    gender=gender,
                    age=int(age) if age else None,
                    relationship=relationship,
                    related_to=related_to if relationship != 'self' else None,
                    registered_by=operator
                )
                
                # Handle profile picture if uploaded
                if 'profile_picture' in request.FILES:
                    profile_pic = request.FILES['profile_picture']
                    # Log information about the file
                    logger.info(f"Processing uploaded file: {profile_pic.name}, size: {profile_pic.size}, content_type: {profile_pic.content_type}")
                    user.profile_picture = profile_pic
                
                user.save()
                logger.info(f"User registered successfully: {user.user_id}")
                
                # Add relationship information to success message
                if relationship == 'self':
                    success_msg = f"User {full_name} registered successfully!"
                else:
                    success_msg = f"{full_name} registered successfully as {relationship} of {related_to}!"
                
                messages.success(request, success_msg)
                
                # Redirect to ticket generation page for this user
                return redirect('generate_ticket', user_id=user.user_id)
                
        except Exception as e:
            logger.error(f"Error registering user: {str(e)}")
            messages.error(request, f"Error registering user: {str(e)}")
    
    # For GET requests, display the registration form
    return render(request, 'user_register.html')

@login_required
def users_list(request):
    """Display a list of all registered users"""
    users = TicketUser.objects.all().order_by('-created_at')
    
    # Apply filters directly from request.GET
    gender = request.GET.get('gender')
    date = request.GET.get('date')
    search = request.GET.get('search')
    
    if gender:
        users = users.filter(gender=gender)
    
    if date:
        try:
            # Parse the date string into a date object
            date_obj = datetime.strptime(date, '%Y-%m-%d').date()
            users = users.filter(created_at__date=date_obj)
        except ValueError:
            # If date is invalid, ignore this filter
            pass
    
    if search:
        users = users.filter(
            full_name__icontains=search
        ) | users.filter(
            email__icontains=search
        ) | users.filter(
            cnic_number__icontains=search
        )
    
    # Get gender counts - always show total counts regardless of filters
    male_count = TicketUser.objects.filter(gender=TicketUser.MALE).count()
    female_count = TicketUser.objects.filter(gender=TicketUser.FEMALE).count()
    
    # Pagination
    paginator = Paginator(users, 10)  # Show 10 users per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'total_count': users.count(),
        'male_count': male_count,
        'female_count': female_count,
    }
    
    return render(request, 'users.html', context)

@login_required
def user_detail(request, user_id):
    """Display details for a specific user"""
    user = get_object_or_404(TicketUser, user_id=user_id)
    tickets = user.tickets.all()
    
    context = {
        'user': user,
        'tickets': tickets,
    }
    
    return render(request, 'user_detail.html', context)

@login_required
def edit_user(request, user_id):
    """Edit an existing user"""
    user = get_object_or_404(TicketUser, user_id=user_id)
    
    if request.method == 'POST':
        # Extract form data
        full_name = request.POST.get('full_name')
        father_name = request.POST.get('father_name')
        email = request.POST.get('email')
        phone_number = request.POST.get('phone_number')
        cnic_number = request.POST.get('cnic_number')
        gender = request.POST.get('gender')
        age = request.POST.get('age')
        
        # Validate email uniqueness (excluding current user)
        if TicketUser.objects.filter(email=email).exclude(user_id=user_id).exists():
            messages.error(request, "Email address is already taken by another user.")
            return render(request, 'edit_user.html', {'user': user})
        
        # # Validate CNIC uniqueness (excluding current user)
        # if TicketUser.objects.filter(cnic_number=cnic_number).exclude(user_id=user_id).exists():
        #     messages.error(request, "CNIC number is already taken by another user.")
        #     return render(request, 'edit_user.html', {'user': user})
        
        try:
            # Update user fields
            user.full_name = full_name
            user.father_name = father_name
            user.email = email
            user.phone_number = phone_number
            user.cnic_number = cnic_number
            user.gender = gender
            user.age = age if age else None
            
            # Handle profile picture if uploaded
            if 'profile_picture' in request.FILES:
                user.profile_picture = request.FILES['profile_picture']
            
            user.save()
            messages.success(request, f"User {user.full_name} updated successfully!")
            return redirect('user_detail', user_id=user.user_id)
            
        except Exception as e:
            logger.error(f"Error updating user: {str(e)}")
            messages.error(request, f"Error updating user: {str(e)}")
    
    return render(request, 'edit_user.html', {'user': user})

@login_required
def delete_user(request, user_id):
    """Delete a user and all associated tickets"""
    if request.method == 'POST':
        user = get_object_or_404(TicketUser, user_id=user_id)
        
        try:
            # Wrap deletion in transaction to ensure atomicity
            with transaction.atomic():
                # Get ticket count for message
                ticket_count = user.tickets.count()
                
                # Delete all tickets associated with user first
                # (This will cascade to delete scan logs as well)
                user.tickets.all().delete()
                
                # Delete the user
                username = user.full_name
                user.delete()
                
                messages.success(request, f"User {username} and {ticket_count} associated tickets deleted successfully.")
        except Exception as e:
            logger.error(f"Error deleting user: {str(e)}")
            messages.error(request, f"Error deleting user: {str(e)}")
    
    return redirect('users_list')


@login_required
def generate_ticket(request, user_id):
    """Generate a ticket with quota checking"""
    user = get_object_or_404(TicketUser, user_id=user_id)
    
    # Check if the user was registered by this operator or if admin
    if (hasattr(request.user, 'operator_profile') and 
        user.registered_by != request.user.operator_profile and 
        not is_admin(request.user)):
        messages.error(request, "You don't have permission to generate a ticket for this user.")
        return redirect('operator_dashboard')
    
    if request.method == 'POST':
        form = TicketForm(request.POST)
        if form.is_valid():
            try:
                # Check quota before creating ticket
                ticket_type = form.cleaned_data['ticket_type']
                quota = TicketQuota.objects.get(ticket_type=ticket_type)
                
                if quota.remaining <= 0:
                    messages.error(request, f"Sorry, no more tickets available for {ticket_type}.")
                    return redirect('generate_ticket', user_id=user.user_id)
                
                # Create the ticket with a database transaction to ensure atomicity
                with transaction.atomic():
                    ticket = form.save(commit=False)
                    ticket.user = user
                    ticket.created_by = request.user
                    
                    # Make sure registered_by is set (from the user, not ticket)
                    # The user's registered_by field should be set correctly
                    
                    ticket.save()
                    
                    # Update quota
                    quota.sold_quantity += 1
                    quota.save()
                    
                    # Generate QR code
                    qr_data = f"{settings.SITE_URL}/verify/{ticket.ticket_id}/"
                    if generate_qr_code(qr_data, ticket):
                        messages.success(request, "Ticket generated successfully!")
                    else:
                        messages.warning(request, "Ticket created but QR code generation failed.")
                    
                    return redirect('ticket_detail', ticket_id=ticket.ticket_id)
            except Exception as e:
                logger.error(f"Error generating ticket: {str(e)}")
                messages.error(request, f"Error generating ticket: {str(e)}")
    else:
        form = TicketForm()
    
    context = {
        'form': form,
        'user': user,
    }
    
    return render(request, 'generate_ticket.html', context)

@login_required
def ticket_detail(request, ticket_id):
    """Display details for a specific ticket"""
    ticket = get_object_or_404(Ticket, ticket_id=ticket_id)
    scan_logs = ticket.scan_logs.all().order_by('-scanned_at')
    
    context = {
        'ticket': ticket,
        'user': ticket.user,
        'scan_logs': scan_logs,
    }
    
    return render(request, 'ticket_detail.html', context)

@login_required
# def print_ticket(request, ticket_id):
#     """Display a printable version of a ticket"""
#     ticket = get_object_or_404(Ticket, ticket_id=ticket_id)
    
#     context = {
#         'ticket': ticket,
#         'user': ticket.user,
#     }
    
#     return render(request, 'print_ticket.html', context)
def print_ticket(request, ticket_id):
    """Display a printable version of a ticket"""
    ticket = get_object_or_404(Ticket, ticket_id=ticket_id)
    
    # Determine design based on ticket type
    ticket_design = "gawader" if ticket.ticket_type == Ticket.GAWADER_ENCLOSURE else "chaman"
    
    context = {
        'ticket': ticket,
        'user': ticket.user,
        'ticket_design': ticket_design
    }
    
    return render(request, 'print_ticket.html', context)

@login_required
def scan_monitor(request):
    """Display the scan monitor page and handle ticket scanning"""
    form = ScanTicketForm()
    
    # Get recent scans for display
    recent_scans = ScanLog.objects.order_by('-scanned_at')[:15]
    
    # Get scan statistics
    scan_stats = {
        'scanned': ScanLog.objects.count(),
        'remaining': Ticket.objects.filter(status=Ticket.UNSCANNED).count(),
        'gate1_count': ScanLog.objects.filter(gate=ScanLog.GATE1).count(),
        'gate2_count': ScanLog.objects.filter(gate=ScanLog.GATE2).count(),
    }
    
    context = {
        'form': form,
        'recent_scans': recent_scans,
        'stats': scan_stats,
    }
    
    return render(request, 'scan_monitor.html', context)

@login_required
@require_POST
def process_scan(request):
    """Process a ticket scan via AJAX"""
    
    # Debug the received data
    logger.info(f"Scan data received: {request.POST.get('ticket_id', 'No ID received')}")
    
    form = ScanTicketForm(request.POST)
    
    if form.is_valid():
        ticket_id = form.cleaned_data['ticket_id']
        gate = form.cleaned_data['gate']
        notes = form.cleaned_data['notes']
        
        logger.info(f"Processing scan for ticket ID: {ticket_id}")
        
        try:
            # Process the scan
            success, message, scan_log = process_ticket_scan(
                ticket_id=ticket_id,
                gate=gate,
                scanned_by=request.user,
                notes=notes
            )
            
            if scan_log:
                # If successful, prepare data for response
                response_data = {
                    'success': success,
                    'message': message,
                    'ticket_id': str(scan_log.ticket.ticket_id),
                    'user_name': scan_log.ticket.user.full_name,
                    'gate': scan_log.get_gate_display(),
                    'time': scan_log.scanned_at.strftime('%H:%M:%S'),
                    'status': scan_log.ticket.get_status_display(),
                    'is_tampered': scan_log.ticket.is_tampered,
                }
            else:
                # If failed, return error message
                response_data = {
                    'success': success,
                    'message': message,
                }
            
            return JsonResponse(response_data)
        except Exception as e:
            logger.error(f"Error processing scan: {str(e)}")
            return JsonResponse({
                'success': False,
                'message': f"Error processing scan: {str(e)}"
            })
    else:
        # Form validation errors - provide detailed error information
        errors = form.errors.as_json()
        logger.error(f"Form validation error: {errors}")
        logger.error(f"Received ticket_id: {request.POST.get('ticket_id', 'None')}")
        
        return JsonResponse({
            'success': False,
            'message': f"Invalid form data: {form.errors}"
        })

@login_required
def ticket_stats(request):
    """Display ticket statistics and reports"""
    report_form = ReportForm()
    
    # Get all statistics for display
    tickets = Ticket.objects.all()
    total_tickets = tickets.count()
    scanned_tickets = tickets.exclude(status=Ticket.UNSCANNED).count()
    unscanned_tickets = tickets.filter(status=Ticket.UNSCANNED).count()
    tampered_tickets = tickets.filter(is_tampered=True).count()
    
    # Get gender statistics
    male_tickets = tickets.filter(user__gender=TicketUser.MALE).count()
    female_tickets = tickets.filter(user__gender=TicketUser.FEMALE).count()
    other_tickets = tickets.filter(user__gender=TicketUser.OTHER).count()
    
    # Get ticket types
    gawader_tickets = tickets.filter(ticket_type=Ticket.GAWADER_ENCLOSURE).count()
    chaman_tickets = tickets.filter(ticket_type=Ticket.CHAMAN_ENCLOSURE).count()
    
    # Get gate statistics
    gate1_scans = ScanLog.objects.filter(gate=ScanLog.GATE1).count()
    gate2_scans = ScanLog.objects.filter(gate=ScanLog.GATE2).count()
    
    # Calculate percentages for charts
    sold_percentage = (scanned_tickets / total_tickets * 100) if total_tickets > 0 else 0
    
    # Calculate gate percentage
    gate_percentage = (gate2_scans / gate1_scans * 100) if gate1_scans > 0 else 0
    
    # Calculate tampered percentage
    tampered_percentage = (tampered_tickets / total_tickets * 100) if total_tickets > 0 else 0
    
    gender_data = {
        'male': male_tickets,
        'female': female_tickets,
        'other': other_tickets
    }
    
    ticket_type_data = {
        'gwader': gawader_tickets,
        'chaman': chaman_tickets
    }
    
    context = {
        'report_form': report_form,
        'total_tickets': total_tickets,
        'scanned_tickets': scanned_tickets,
        'unscanned_tickets': unscanned_tickets,
        'tampered_tickets': tampered_tickets,
        'gender_data': gender_data,
        'ticket_type_data': ticket_type_data,
        'gate1_scans': gate1_scans,
        'gate2_scans': gate2_scans,
        'sold_percentage': sold_percentage,
        'gate_percentage': gate_percentage,
        'tampered_percentage': tampered_percentage,
    }
    
    return render(request, 'ticket_stats.html', context)



@login_required
def ticket_list(request):
    """Display all tickets with filtering options"""
    # Get base queryset
    tickets_queryset = Ticket.objects.all().select_related('user', 'user__registered_by')
    
    # If not admin, limit to tickets registered by this operator
    if not is_admin(request.user) and hasattr(request.user, 'operator_profile'):
        operator = request.user.operator_profile
        tickets_queryset = tickets_queryset.filter(user__registered_by=operator)
    
    # Apply filters
    ticket_type = request.GET.get('ticket_type')
    status = request.GET.get('status')
    operator_id = request.GET.get('operator')
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    search = request.GET.get('search')

    # Get base queryset with created_by information
    tickets_queryset = Ticket.objects.all().select_related(
        'user', 
        'user__registered_by',
        'created_by'  # Add this to fetch the creator info
    )
    
    # Filter by ticket type if provided
    if ticket_type:
        tickets_queryset = tickets_queryset.filter(ticket_type=ticket_type)
    
    # Filter by status if provided
    if status:
        tickets_queryset = tickets_queryset.filter(status=status)
    
    # Filter by operator if provided
    if operator_id:
        tickets_queryset = tickets_queryset.filter(user__registered_by_id=operator_id)
    
    # Filter by date range if provided
    if date_from:
        try:
            from datetime import datetime
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            tickets_queryset = tickets_queryset.filter(created_at__date__gte=date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            from datetime import datetime
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            tickets_queryset = tickets_queryset.filter(created_at__date__lte=date_to_obj)
        except ValueError:
            pass
    
    # Filter by search term if provided
    if search:
        from django.db.models import Q
        tickets_queryset = tickets_queryset.filter(
            Q(ticket_id__icontains=search) | 
            Q(user__full_name__icontains=search) | 
            Q(user__cnic_number__icontains=search)
        )
    
    # Calculate ticket statistics
    total_tickets = tickets_queryset.count()
    gawader_tickets = tickets_queryset.filter(ticket_type=Ticket.GAWADER_ENCLOSURE).count()
    chaman_tickets = tickets_queryset.filter(ticket_type=Ticket.CHAMAN_ENCLOSURE).count()
    
    # Calculate total revenue
    from django.db.models import Sum
    total_revenue = tickets_queryset.aggregate(total=Sum('price'))['total'] or 0
    
    # Get all operators for the filter dropdown
    operators = Operator.objects.filter(is_active=True).order_by('name')
    
    # Paginate results
    paginator = Paginator(tickets_queryset.order_by('-created_at'), 25)  # 25 tickets per page
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'total_tickets': total_tickets,
        'gawader_tickets': gawader_tickets,
        'chaman_tickets': chaman_tickets,
        'total_revenue': total_revenue,
        'operators': operators
    }
    
    return render(request, 'ticket_list.html', context)

@login_required
@user_passes_test(is_admin)
def fix_operator_relationships(request):
    """Fix missing relationships between users and operators"""
    # Get all operators and their associated users
    operators = {}
    for user in User.objects.filter(operator_profile__isnull=False):
        operators[user.username] = user.operator_profile
    
    # Update ticket users based on ticket creator
    updated_users = 0
    for ticket in Ticket.objects.select_related('user', 'created_by'):
        if ticket.created_by and ticket.created_by.username in operators:
            operator = operators[ticket.created_by.username]
            if ticket.user and not ticket.user.registered_by:
                ticket.user.registered_by = operator
                ticket.user.save()
                updated_users += 1
    
    messages.success(request, f"Updated registered_by for {updated_users} users")
    return redirect('admin_dashboard')

def debug_ticket_operators(request):
    """Debug view to check ticket operator relationships"""
    tickets = Ticket.objects.all().select_related('user', 'created_by')[:10]
    
    debug_info = []
    for ticket in tickets:
        ticket_info = {
            'ticket_id': ticket.ticket_id,
            'created_by_username': ticket.created_by.username if ticket.created_by else "None",
            'created_by_has_operator': hasattr(ticket.created_by, 'operator_profile') if ticket.created_by else False,
            'user_name': ticket.user.full_name if ticket.user else "None",
            'user_has_registered_by': hasattr(ticket.user, 'registered_by') if ticket.user else False,
            'user_registered_by': ticket.user.registered_by.name if ticket.user and hasattr(ticket.user, 'registered_by') and ticket.user.registered_by else "None"
        }
        debug_info.append(ticket_info)
    
    return render(request, 'debug_operators.html', {'debug_info': debug_info})


@login_required
def ticket_search(request):
    """Search for tickets by QR scanning or manual search"""
    ticket = None
    user = None
    related_tickets = []
    scan_logs = []
    search_performed = False
    
    if request.method == 'POST' or request.GET.get('ticket_id'):
        search_performed = True
        ticket_id = request.POST.get('ticket_id') or request.GET.get('ticket_id')
        
        # Remove T: prefix if present (from scanner)
        if ticket_id and ticket_id.startswith("T:"):
            ticket_id = ticket_id[2:]
        
        try:
            # Try to convert to UUID
            ticket_uuid = uuid.UUID(ticket_id)
            
            # Get the ticket and related information
            try:
                ticket = Ticket.objects.get(ticket_id=ticket_uuid)
                user = ticket.user
                scan_logs = ticket.scan_logs.all().order_by('-scanned_at')
                
                # Find related tickets (same CNIC but different users, or specified relationships)
                if user.relationship == 'self':
                    # For primary users, find all family members using their CNIC
                    related_tickets = Ticket.objects.filter(
                        user__cnic_number=user.cnic_number
                    ).exclude(ticket_id=ticket.ticket_id).select_related('user')
                    
                    # Also find tickets where this user is listed as a related person
                    related_users = TicketUser.objects.filter(related_to__icontains=user.full_name)
                    for related_user in related_users:
                        related_user_tickets = related_user.tickets.all()
                        related_tickets = list(related_tickets) + list(related_user_tickets)
                else:
                    # For non-primary users, find the primary user and their tickets
                    primary_users = TicketUser.objects.filter(
                        cnic_number=user.cnic_number, 
                        relationship='self'
                    )
                    for primary_user in primary_users:
                        primary_tickets = primary_user.tickets.all()
                        related_tickets = list(related_tickets) + list(primary_tickets)
                    
                    # Also find other family members with the same CNIC
                    family_users = TicketUser.objects.filter(
                        cnic_number=user.cnic_number
                    ).exclude(user_id=user.user_id)
                    for family_user in family_users:
                        family_tickets = family_user.tickets.all()
                        related_tickets = list(related_tickets) + list(family_tickets)
                        
            except Ticket.DoesNotExist:
                messages.error(request, "Ticket not found.")
                
        except (ValueError, TypeError):
            messages.error(request, "Invalid ticket ID format.")
    
    context = {
        'ticket': ticket,
        'user': user,
        'related_tickets': related_tickets,
        'scan_logs': scan_logs,
        'search_performed': search_performed
    }
    
    return render(request, 'ticket_search.html', context)


@login_required
def delete_ticket(request, ticket_id):
    """Delete a ticket"""
    if request.method == 'POST':
        ticket = get_object_or_404(Ticket, ticket_id=ticket_id)
        user = ticket.user
        
        try:
            # Store information for success message
            ticket_type = ticket.get_ticket_type_display()
            user_name = user.full_name
            
            # Delete the ticket
            ticket.delete()
            
            messages.success(request, f"Ticket ({ticket_type}) for {user_name} has been deleted successfully.")
            
            # Check if we should redirect to user detail or back to ticket list
            referer = request.META.get('HTTP_REFERER', '')
            if 'user' in referer:
                return redirect('user_detail', user_id=user.user_id)
            else:
                return redirect('ticket_list')
                
        except Exception as e:
            logger.error(f"Error deleting ticket: {str(e)}")
            messages.error(request, f"Error deleting ticket: {str(e)}")
            return redirect('ticket_list')
    
    # If not POST, redirect to ticket list
    return redirect('ticket_list')

def generate_report(request):
    """Generate and download a report"""
    if request.method == 'POST':
        form = ReportForm(request.POST)
        if form.is_valid():
            report_type = form.cleaned_data['report_type']
            report_format = form.cleaned_data['report_format']
            date_from = form.cleaned_data.get('date_from')
            date_to = form.cleaned_data.get('date_to')
            
            # Base queryset
            queryset = Ticket.objects.all()
            
            # Apply report type filter
            if report_type == 'scanned_tickets':
                queryset = queryset.exclude(status=Ticket.UNSCANNED)
            elif report_type == 'unscanned_tickets':
                queryset = queryset.filter(status=Ticket.UNSCANNED)
            elif report_type == 'tampered_tickets':
                queryset = queryset.filter(is_tampered=True)
            
            # Apply date range filter if provided
            if date_from:
                queryset = queryset.filter(created_at__date__gte=date_from)
            if date_to:
                queryset = queryset.filter(created_at__date__lte=date_to)
            
            # Generate the appropriate report
            if report_format == 'csv':
                # Create CSV response
                response = HttpResponse(content_type='text/csv')
                response['Content-Disposition'] = f'attachment; filename="{report_type}_{datetime.now().strftime("%Y%m%d")}.csv"'
                
                csv_data = export_tickets_to_csv(queryset)
                response.write(csv_data)
                
                return response
            elif report_format == 'pdf':
                # For PDF, you would integrate with a PDF generation library
                # This is a placeholder - you'll need to implement actual PDF generation
                messages.warning(request, "PDF generation not implemented yet.")
                return redirect('ticket_stats')
    
    # If form invalid or not POST, redirect back to stats
    return redirect('ticket_stats')


def settings_view(request):
    """Display and update system settings"""
    # For simplicity, we'll just display the settings template
    # In a real implementation, you'd have a form to update settings
    return render(request, 'settings.html')

def verify_ticket(request, ticket_id):

    """Public endpoint to verify a ticket (accessible from QR code)"""
    try:
        ticket = Ticket.objects.get(ticket_id=ticket_id)
        
        # Get scan logs
        gate1_scan = ticket.scan_logs.filter(gate=ScanLog.GATE1).first()
        gate2_scan = ticket.scan_logs.filter(gate=ScanLog.GATE2).first()
        
        context = {
            'ticket': ticket,
            'user': ticket.user,
            'gate1_scan': gate1_scan,
            'gate2_scan': gate2_scan,
            'is_valid': True,
        }
        
        return render(request, 'verify_ticket.html', context)
    
    except Ticket.DoesNotExist:
        context = {
            'is_valid': False,
            'message': 'Invalid ticket ID. This ticket does not exist.',
        }
        return render(request, 'verify_ticket.html', context)
    
    except Exception as e:
        context = {
            'is_valid': False,
            'message': f'Error verifying ticket: {str(e)}',
        }
        return render(request, 'verify_ticket.html', context)

from django.contrib.auth.decorators import login_required, user_passes_test
from .models import Operator, TicketQuota


@login_required
@user_passes_test(is_operator)
@login_required
@user_passes_test(is_operator)
def operator_dashboard(request):
    """Dashboard for operators"""
    operator = request.user.operator_profile
    
    # Get quota information with error handling
    try:
        gawader_quota = TicketQuota.objects.get(ticket_type=Ticket.GAWADER_ENCLOSURE)
    except TicketQuota.DoesNotExist:
        # Create a default quota if it doesn't exist
        gawader_quota = TicketQuota.objects.create(
            ticket_type=Ticket.GAWADER_ENCLOSURE,
            total_quantity=1750,
            sold_quantity=0
        )
    
    try:
        chaman_quota = TicketQuota.objects.get(ticket_type=Ticket.CHAMAN_ENCLOSURE)
    except TicketQuota.DoesNotExist:
        # Create a default quota if it doesn't exist
        chaman_quota = TicketQuota.objects.create(
            ticket_type=Ticket.CHAMAN_ENCLOSURE,
            total_quantity=1750,
            sold_quantity=0
        )
    
    # Rest of your view function...
    
    # Get operator statistics
    users_registered = operator.count_registered_users()
    gawader_tickets = operator.count_generated_tickets(Ticket.GAWADER_ENCLOSURE)
    chaman_tickets = operator.count_generated_tickets(Ticket.CHAMAN_ENCLOSURE)
    total_tickets = gawader_tickets + chaman_tickets
    
    # Get recent activities
    recent_users = TicketUser.objects.filter(registered_by=operator).order_by('-created_at')[:5]
    recent_tickets = Ticket.objects.filter(user__registered_by=operator).order_by('-created_at')[:5]
    
    context = {
        'operator': operator,
        'users_registered': users_registered,
        'gawader_tickets': gawader_tickets,
        'chaman_tickets': chaman_tickets,
        'total_tickets': total_tickets,
        'gawader_quota': gawader_quota,
        'chaman_quota': chaman_quota,
        'recent_users': recent_users,
        'recent_tickets': recent_tickets,
    }
    
    return render(request, 'operator_dashboard.html', context)
@login_required
@user_passes_test(is_operator)
def operator_users(request):
    """Display users registered by this operator"""
    operator = request.user.operator_profile
    
    # Get base queryset - only users registered by this operator
    users_queryset = TicketUser.objects.filter(registered_by=operator)
    
    # Apply filters
    gender = request.GET.get('gender')
    relationship = request.GET.get('relationship')
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    search = request.GET.get('search')
    
    # Filter by gender if provided
    if gender and gender != 'All':
        users_queryset = users_queryset.filter(gender=gender)
    
    # Filter by relationship if provided
    if relationship and relationship != 'All':
        users_queryset = users_queryset.filter(relationship=relationship)
    
    # Filter by date range if provided
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            users_queryset = users_queryset.filter(created_at__date__gte=date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            users_queryset = users_queryset.filter(created_at__date__lte=date_to_obj)
        except ValueError:
            pass
    
    # Filter by search term if provided
    if search:
        users_queryset = users_queryset.filter(
            Q(full_name__icontains=search) | 
            Q(cnic_number__icontains=search) | 
            Q(email__icontains=search)
        )
    
    # Order by most recent first
    users_queryset = users_queryset.order_by('-created_at')
    
    # Add debug information
    print(f"Operator: {operator.name}, User count: {users_queryset.count()}")
    
    # Paginate results
    paginator = Paginator(users_queryset, 20)  # 20 users per page
    page_number = request.GET.get('page', 1)
    users_page = paginator.get_page(page_number)
    
    context = {
        'operator': operator,
        'users': users_page,
        'total_count': users_queryset.count(),
    }
    
    return render(request, 'operator_users.html', context)

@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    """Admin dashboard with system-wide statistics"""
    # Get overall stats
    total_users = TicketUser.objects.count()
    total_tickets = Ticket.objects.count()
    
    # Get overall stats
    total_users = TicketUser.objects.count()
    total_tickets = Ticket.objects.count()
    
    # Get quotas
    quotas = TicketQuota.objects.all()
    
    # Calculate percentages for each quota
    for quota in quotas:
        if quota.total_quantity > 0:
            quota.percentage = (quota.sold_quantity / quota.total_quantity) * 100
        else:
            quota.percentage = 0

    # Get quotas
    quotas = TicketQuota.objects.all()
    
    # Get operator stats
    operators = Operator.objects.all()
    operator_stats = []
    
    for operator in operators:
        stats = {
            'operator': operator,
            'users': operator.count_registered_users(),
            'tickets': {
                'total': operator.count_generated_tickets(),
                'gawader': operator.count_generated_tickets(Ticket.GAWADER_ENCLOSURE),
                'chaman': operator.count_generated_tickets(Ticket.CHAMAN_ENCLOSURE),
            }
        }
        operator_stats.append(stats)
    
    context = {
        'total_users': total_users,
        'total_tickets': total_tickets,
        'quotas': quotas,
        'operator_stats': operator_stats,
    }
    
    return render(request, 'admin_dashboard.html', context)

@login_required
@user_passes_test(is_admin)
def quota_management(request):
    """Manage ticket quotas"""
    if request.method == 'POST':
        quota_id = request.POST.get('quota_id')
        new_total = request.POST.get('total_quantity')
        
        if quota_id and new_total:
            try:
                quota = TicketQuota.objects.get(id=quota_id)
                quota.total_quantity = int(new_total)
                quota.save()
                messages.success(request, f"Quota for {quota.ticket_type} updated successfully.")
            except Exception as e:
                messages.error(request, f"Error updating quota: {str(e)}")
    
    quotas = TicketQuota.objects.all()
    context = {
        'quotas': quotas,
    }
    
    return render(request, 'quota_management.html', context)

# Add this to your views.py file

@login_required

@user_passes_test(is_admin)
def financial_reports(request):
    """Display financial reports and statistics"""
    from django.db.models import Count, Sum, F, Value, CharField, Q
    from django.db.models.functions import TruncDate, Concat
    
    # Date filtering
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    
    # Base queryset - include tickets regardless of operator status
    tickets_queryset = Ticket.objects.all().select_related('user', 'user__registered_by', 'created_by')
    
    # Apply date filters if provided
    if date_from:
        try:
            from datetime import datetime
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            tickets_queryset = tickets_queryset.filter(created_at__date__gte=date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            from datetime import datetime
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            tickets_queryset = tickets_queryset.filter(created_at__date__lte=date_to_obj)
        except ValueError:
            pass
    
    # Overall summary
    total_tickets = tickets_queryset.count()
    total_revenue = tickets_queryset.aggregate(total=Sum('price'))['total'] or 0
    gawader_count = tickets_queryset.filter(ticket_type=Ticket.GAWADER_ENCLOSURE).count()
    chaman_count = tickets_queryset.filter(ticket_type=Ticket.CHAMAN_ENCLOSURE).count()
    gawader_revenue = tickets_queryset.filter(ticket_type=Ticket.GAWADER_ENCLOSURE).aggregate(total=Sum('price'))['total'] or 0
    chaman_revenue = tickets_queryset.filter(ticket_type=Ticket.CHAMAN_ENCLOSURE).aggregate(total=Sum('price'))['total'] or 0
    
    # Sales by operator or admin - modify this section
    # First get tickets with operator info
    operator_tickets = tickets_queryset.filter(
        created_by__operator_profile__isnull=False
    ).values(
        'created_by__operator_profile__name',
        'created_by__operator_profile__id',
        'ticket_type'
    ).annotate(
        tickets_count=Count('ticket_id'),
        total_amount=Sum('price'),
        operator_name=F('created_by__operator_profile__name')
    )
    
    # Get admin tickets
    admin_tickets = tickets_queryset.filter(
        created_by__is_staff=True, 
        created_by__operator_profile__isnull=True
    ).values(
        'ticket_type'
    ).annotate(
        tickets_count=Count('ticket_id'),
        total_amount=Sum('price'),
        operator_name=Value('Admin', output_field=CharField())
    ).annotate(
        created_by__operator_profile__id=Value(0, output_field=CharField())
    )
    
    # Combine operator and admin tickets
    sales_by_operator = list(operator_tickets) + list(admin_tickets)
    
    # Process operator stats for easier display
    operators_summary = {}
    for sale in sales_by_operator:
        operator_id = sale.get('created_by__operator_profile__id', 'admin')
        operator_name = sale.get('operator_name', 'Admin')
        
        if operator_id not in operators_summary:
            operators_summary[operator_id] = {
                'id': operator_id,
                'name': operator_name,
                'total_tickets': 0,
                'total_revenue': 0,
                'gawader_tickets': 0,
                'gawader_revenue': 0,
                'chaman_tickets': 0,
                'chaman_revenue': 0
            }
        
        operators_summary[operator_id]['total_tickets'] += sale['tickets_count']
        operators_summary[operator_id]['total_revenue'] += sale['total_amount']
        
        if sale['ticket_type'] == Ticket.GAWADER_ENCLOSURE:
            operators_summary[operator_id]['gawader_tickets'] += sale['tickets_count']
            operators_summary[operator_id]['gawader_revenue'] += sale['total_amount']
        elif sale['ticket_type'] == Ticket.CHAMAN_ENCLOSURE:
            operators_summary[operator_id]['chaman_tickets'] += sale['tickets_count']
            operators_summary[operator_id]['chaman_revenue'] += sale['total_amount']
    
    # Daily sales data (for charts) - include all tickets
    daily_sales = (
        tickets_queryset
        .annotate(date=TruncDate('created_at'))
        .values('date', 'ticket_type')
        .annotate(
            count=Count('ticket_id'),
            revenue=Sum('price')
        )
        .order_by('date', 'ticket_type')
    )
    
    # Process daily sales for the chart
    dates = set()
    daily_data = {
        Ticket.GAWADER_ENCLOSURE: {},
        Ticket.CHAMAN_ENCLOSURE: {}
    }
    
    for sale in daily_sales:
        if sale['date']:
            date_str = sale['date'].strftime('%Y-%m-%d')
            dates.add(date_str)
            daily_data[sale['ticket_type']][date_str] = {
                'count': sale['count'],
                'revenue': sale['revenue']
            }
    
    # Fill in missing dates
    sorted_dates = sorted(dates)
    chart_data = []
    
    for date_str in sorted_dates:
        gawader_data = daily_data[Ticket.GAWADER_ENCLOSURE].get(date_str, {'count': 0, 'revenue': 0})
        chaman_data = daily_data[Ticket.CHAMAN_ENCLOSURE].get(date_str, {'count': 0, 'revenue': 0})
        
        chart_data.append({
            'date': date_str,
            'gawader_count': gawader_data['count'],
            'gawader_revenue': gawader_data['revenue'],
            'chaman_count': chaman_data['count'],
            'chaman_revenue': chaman_data['revenue'],
            'total_count': gawader_data['count'] + chaman_data['count'],
            'total_revenue': gawader_data['revenue'] + chaman_data['revenue']
        })
    
    # Recent ticket sales (last 20)
    recent_tickets = (
        tickets_queryset
        .select_related('user', 'user__registered_by', 'created_by')
        .order_by('-created_at')[:20]
    )
    
    context = {
        'total_tickets': total_tickets,
        'total_revenue': total_revenue,
        'gawader_count': gawader_count,
        'chaman_count': chaman_count,
        'gawader_revenue': gawader_revenue,
        'chaman_revenue': chaman_revenue,
        'operators': list(operators_summary.values()),
        'chart_data': chart_data,
        'recent_tickets': recent_tickets,
        'date_from': date_from,
        'date_to': date_to
    }
    
    return render(request, 'financial_reports.html', context)




@login_required
@user_passes_test(is_admin)
def export_financial_report(request):
    """Export financial report to Excel"""
    # Date filtering
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    
    # Base queryset
    tickets_queryset = Ticket.objects.all().select_related('user', 'user__registered_by')
    
    # Apply date filters if provided
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            tickets_queryset = tickets_queryset.filter(created_at__date__gte=date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            tickets_queryset = tickets_queryset.filter(created_at__date__lte=date_to_obj)
        except ValueError:
            pass
    
    # Get all tickets with operator info
    tickets_data = tickets_queryset.values(
        'ticket_id',
        'user__full_name',
        'user__cnic_number',
        'user__registered_by__name',
        'ticket_type',
        'price',
        'status',
        'created_at'
    )
    
    # Convert to DataFrame
    df_tickets = pd.DataFrame(list(tickets_data))
    
    # Rename columns for better readability
    if not df_tickets.empty:
        # Make datetime columns timezone naive
        if 'created_at' in df_tickets.columns:
            df_tickets['created_at'] = df_tickets['created_at'].apply(lambda x: timezone.make_naive(x) if timezone.is_aware(x) else x)
        
        df_tickets = df_tickets.rename(columns={
            'ticket_id': 'Ticket ID',
            'user__full_name': 'User Name',
            'user__cnic_number': 'CNIC',
            'user__registered_by__name': 'Registered By',
            'ticket_type': 'Ticket Type',
            'price': 'Price',
            'status': 'Status',
            'created_at': 'Created On'
        })
    
    # Get operator summary data
    operator_summary = tickets_queryset.values(
        'user__registered_by__name'
    ).annotate(
        tickets_count=Count('ticket_id'),
        total_amount=Sum('price'),
        gawader_tickets=Sum(
            Case(
                When(ticket_type=Ticket.GAWADER_ENCLOSURE, then=1),
                default=0,
                output_field=IntegerField()
            )
        ),
        gawader_amount=Sum(
            Case(
                When(ticket_type=Ticket.GAWADER_ENCLOSURE, then=F('price')),
                default=0,
                output_field=DecimalField(max_digits=10, decimal_places=2)
            )
        ),
        chaman_tickets=Sum(
            Case(
                When(ticket_type=Ticket.CHAMAN_ENCLOSURE, then=1),
                default=0,
                output_field=IntegerField()
            )
        ),
        chaman_amount=Sum(
            Case(
                When(ticket_type=Ticket.CHAMAN_ENCLOSURE, then=F('price')),
                default=0,
                output_field=DecimalField(max_digits=10, decimal_places=2)
            )
        )
    ).order_by('user__registered_by__name')
    
    # Convert to DataFrame
    df_operators = pd.DataFrame(list(operator_summary))
    
    # Rename columns for better readability
    if not df_operators.empty:
        df_operators = df_operators.rename(columns={
            'user__registered_by__name': 'Operator Name',
            'tickets_count': 'Total Tickets',
            'total_amount': 'Total Revenue',
            'gawader_tickets': 'Gawader Tickets',
            'gawader_amount': 'Gawader Revenue',
            'chaman_tickets': 'Chaman Tickets',
            'chaman_amount': 'Chaman Revenue'
        })
    
    # Create a BytesIO buffer
    buffer = io.BytesIO()
    
    # Create Excel writer
    with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
        # Write operators summary to sheet 1
        if not df_operators.empty:
            df_operators.to_excel(writer, sheet_name='Operator Summary', index=False)
            
            # Format the Operator Summary sheet
            workbook = writer.book
            worksheet = writer.sheets['Operator Summary']
            
            # Format currency columns
            money_format = workbook.add_format({'num_format': 'PKR #,##0'})
            for col_num, column in enumerate(df_operators.columns):
                if 'Revenue' in column:
                    worksheet.set_column(col_num, col_num, 18, money_format)
        
        # Write ticket data to sheet 2
        if not df_tickets.empty:
            df_tickets.to_excel(writer, sheet_name='Ticket Details', index=False)
            
            # Format the Ticket Details sheet
            workbook = writer.book
            worksheet = writer.sheets['Ticket Details']
            
            # Format currency columns
            money_format = workbook.add_format({'num_format': 'PKR #,##0'})
            date_format = workbook.add_format({'num_format': 'yyyy-mm-dd hh:mm'})
            
            # Add column formatting
            for col_num, column in enumerate(df_tickets.columns):
                if column == 'Price':
                    worksheet.set_column(col_num, col_num, 12, money_format)
                elif column == 'Created On':
                    worksheet.set_column(col_num, col_num, 20, date_format)
                elif column == 'Ticket ID':
                    worksheet.set_column(col_num, col_num, 40)
                else:
                    worksheet.set_column(col_num, col_num, 18)
        
        # Add summary sheet
        summary_data = {
            'Metric': [
                'Total Tickets',
                'Gawader Tickets',
                'Chaman Tickets',
                'Total Revenue',
                'Gawader Revenue',
                'Chaman Revenue',
                'Report Date Range'
            ],
            'Value': [
                tickets_queryset.count(),
                tickets_queryset.filter(ticket_type=Ticket.GAWADER_ENCLOSURE).count(),
                tickets_queryset.filter(ticket_type=Ticket.CHAMAN_ENCLOSURE).count(),
                tickets_queryset.aggregate(total=Sum('price'))['total'] or 0,
                tickets_queryset.filter(ticket_type=Ticket.GAWADER_ENCLOSURE).aggregate(total=Sum('price'))['total'] or 0,
                tickets_queryset.filter(ticket_type=Ticket.CHAMAN_ENCLOSURE).aggregate(total=Sum('price'))['total'] or 0,
                f"{date_from or 'All'} to {date_to or 'All'}"
            ]
        }
        
        df_summary = pd.DataFrame(summary_data)
        df_summary.to_excel(writer, sheet_name='Summary', index=False)
        
        # Format the Summary sheet
        worksheet = writer.sheets['Summary']
        money_format = workbook.add_format({'num_format': 'PKR #,##0'})
        
        # Format revenue rows
        for row in range(1, 7):
            if 'Revenue' in df_summary.loc[row-1, 'Metric']:
                worksheet.write(row, 1, df_summary.loc[row-1, 'Value'], money_format)
    
    # Set the buffer's position to the beginning
    buffer.seek(0)
    
    # Generate file name with date range
    date_str = ""
    if date_from:
        date_str += f"from_{date_from}"
    if date_to:
        date_str += f"_to_{date_to}"
    
    if not date_str:
        date_str = "all_time"
    
    # Create response
    response = HttpResponse(
        buffer.getvalue(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=IBC_Financial_Report_{date_str}.xlsx'
    
    return response
    """Export financial report to Excel"""
    # Date filtering
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    
    # Base queryset
    tickets_queryset = Ticket.objects.all().select_related('user', 'user__registered_by')
    
    # Apply date filters if provided
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            tickets_queryset = tickets_queryset.filter(created_at__date__gte=date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            tickets_queryset = tickets_queryset.filter(created_at__date__lte=date_to_obj)
        except ValueError:
            pass
    
    # Get all tickets with operator info
    tickets_data = tickets_queryset.values(
        'ticket_id',
        'user__full_name',
        'user__cnic_number',
        'user__registered_by__name',
        'ticket_type',
        'price',
        'status',
        'created_at'
    )
    
    # Convert to DataFrame
    df_tickets = pd.DataFrame(list(tickets_data))
    
    # Rename columns for better readability
    if not df_tickets.empty:
        df_tickets = df_tickets.rename(columns={
            'ticket_id': 'Ticket ID',
            'user__full_name': 'User Name',
            'user__cnic_number': 'CNIC',
            'user__registered_by__name': 'Registered By',
            'ticket_type': 'Ticket Type',
            'price': 'Price',
            'status': 'Status',
            'created_at': 'Created On'
        })
    
    # Get operator summary data
    operator_summary = tickets_queryset.values(
        'user__registered_by__name'
    ).annotate(
        tickets_count=Count('ticket_id'),
        total_amount=Sum('price'),
        gawader_tickets=Sum(
            Case(
                When(ticket_type=Ticket.GAWADER_ENCLOSURE, then=1),
                default=0,
                output_field=IntegerField()
            )
        ),
        gawader_amount=Sum(
            Case(
                When(ticket_type=Ticket.GAWADER_ENCLOSURE, then=F('price')),
                default=0,
                output_field=DecimalField(max_digits=10, decimal_places=2)
            )
        ),
        chaman_tickets=Sum(
            Case(
                When(ticket_type=Ticket.CHAMAN_ENCLOSURE, then=1),
                default=0,
                output_field=IntegerField()
            )
        ),
        chaman_amount=Sum(
            Case(
                When(ticket_type=Ticket.CHAMAN_ENCLOSURE, then=F('price')),
                default=0,
                output_field=DecimalField(max_digits=10, decimal_places=2)
            )
        )
    ).order_by('user__registered_by__name')
    
    # Convert to DataFrame
    df_operators = pd.DataFrame(list(operator_summary))
    
    # Rename columns for better readability
    if not df_operators.empty:
        df_operators = df_operators.rename(columns={
            'user__registered_by__name': 'Operator Name',
            'tickets_count': 'Total Tickets',
            'total_amount': 'Total Revenue',
            'gawader_tickets': 'Gawader Tickets',
            'gawader_amount': 'Gawader Revenue',
            'chaman_tickets': 'Chaman Tickets',
            'chaman_amount': 'Chaman Revenue'
        })
    
    # Create a BytesIO buffer
    buffer = io.BytesIO()
    
    # Create Excel writer
    with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
        # Write operators summary to sheet 1
        if not df_operators.empty:
            df_operators.to_excel(writer, sheet_name='Operator Summary', index=False)
            
            # Format the Operator Summary sheet
            workbook = writer.book
            worksheet = writer.sheets['Operator Summary']
            
            # Format currency columns
            money_format = workbook.add_format({'num_format': 'PKR #,##0'})
            for col_num, column in enumerate(df_operators.columns):
                if 'Revenue' in column:
                    worksheet.set_column(col_num, col_num, 18, money_format)
        
        # Write ticket data to sheet 2
        if not df_tickets.empty:
            df_tickets.to_excel(writer, sheet_name='Ticket Details', index=False)
            
            # Format the Ticket Details sheet
            workbook = writer.book
            worksheet = writer.sheets['Ticket Details']
            
            # Format currency columns
            money_format = workbook.add_format({'num_format': 'PKR #,##0'})
            date_format = workbook.add_format({'num_format': 'yyyy-mm-dd hh:mm'})
            
            # Add column formatting
            for col_num, column in enumerate(df_tickets.columns):
                if column == 'Price':
                    worksheet.set_column(col_num, col_num, 12, money_format)
                elif column == 'Created On':
                    worksheet.set_column(col_num, col_num, 20, date_format)
                elif column == 'Ticket ID':
                    worksheet.set_column(col_num, col_num, 40)
                else:
                    worksheet.set_column(col_num, col_num, 18)
        
        # Add summary sheet
        summary_data = {
            'Metric': [
                'Total Tickets',
                'Gawader Tickets',
                'Chaman Tickets',
                'Total Revenue',
                'Gawader Revenue',
                'Chaman Revenue',
                'Report Date Range'
            ],
            'Value': [
                tickets_queryset.count(),
                tickets_queryset.filter(ticket_type=Ticket.GAWADER_ENCLOSURE).count(),
                tickets_queryset.filter(ticket_type=Ticket.CHAMAN_ENCLOSURE).count(),
                tickets_queryset.aggregate(total=Sum('price'))['total'] or 0,
                tickets_queryset.filter(ticket_type=Ticket.GAWADER_ENCLOSURE).aggregate(total=Sum('price'))['total'] or 0,
                tickets_queryset.filter(ticket_type=Ticket.CHAMAN_ENCLOSURE).aggregate(total=Sum('price'))['total'] or 0,
                f"{date_from or 'All'} to {date_to or 'All'}"
            ]
        }
        
        df_summary = pd.DataFrame(summary_data)
        df_summary.to_excel(writer, sheet_name='Summary', index=False)
        
        # Format the Summary sheet
        worksheet = writer.sheets['Summary']
        money_format = workbook.add_format({'num_format': 'PKR #,##0'})
        
        # Format revenue rows
        for row in range(1, 7):
            if 'Revenue' in df_summary.loc[row-1, 'Metric']:
                worksheet.write(row, 1, df_summary.loc[row-1, 'Value'], money_format)
    
    # Set the buffer's position to the beginning
    buffer.seek(0)
    
    # Generate file name with date range
    date_str = ""
    if date_from:
        date_str += f"from_{date_from}"
    if date_to:
        date_str += f"_to_{date_to}"
    
    if not date_str:
        date_str = "all_time"
    
    # Create response
    response = HttpResponse(
        buffer.getvalue(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=IBC_Financial_Report_{date_str}.xlsx'
    
    return response
    
    # Date filtering
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    
    # Base queryset
    tickets_queryset = Ticket.objects.all().select_related('user', 'user__registered_by')
    
    # Apply date filters if provided
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            tickets_queryset = tickets_queryset.filter(created_at__date__gte=date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            tickets_queryset = tickets_queryset.filter(created_at__date__lte=date_to_obj)
        except ValueError:
            pass
    
    # Get all tickets with operator info
    tickets_data = tickets_queryset.values(
        'ticket_id',
        'user__full_name',
        'user__cnic_number',
        'user__registered_by__name',
        'ticket_type',
        'price',
        'status',
        'created_at'
    )
    
    # Convert to DataFrame
    df_tickets = pd.DataFrame(list(tickets_data))
    
    # Rename columns for better readability
    if not df_tickets.empty:
        df_tickets = df_tickets.rename(columns={
            'ticket_id': 'Ticket ID',
            'user__full_name': 'User Name',
            'user__cnic_number': 'CNIC',
            'user__registered_by__name': 'Registered By',
            'ticket_type': 'Ticket Type',
            'price': 'Price',
            'status': 'Status',
            'created_at': 'Created On'
        })
    
    # Get operator summary data
    operator_summary = tickets_queryset.values(
        'user__registered_by__name'
    ).annotate(
        tickets_count=Count('ticket_id'),
        total_amount=Sum('price'),
        gawader_tickets=Sum(
            Case(
                When(ticket_type=Ticket.GAWADER_ENCLOSURE, then=1),
                default=0,
                output_field=models.IntegerField()
            )
        ),
        gawader_amount=Sum(
            Case(
                When(ticket_type=Ticket.GAWADER_ENCLOSURE, then=F('price')),
                default=0,
                output_field=models.DecimalField(max_digits=10, decimal_places=2)
            )
        ),
        chaman_tickets=Sum(
            Case(
                When(ticket_type=Ticket.CHAMAN_ENCLOSURE, then=1),
                default=0,
                output_field=models.IntegerField()
            )
        ),
        chaman_amount=Sum(
            Case(
                When(ticket_type=Ticket.CHAMAN_ENCLOSURE, then=F('price')),
                default=0,
                output_field=models.DecimalField(max_digits=10, decimal_places=2)
            )
        )
    ).order_by('user__registered_by__name')
    
    # Convert to DataFrame
    df_operators = pd.DataFrame(list(operator_summary))
    
    # Rename columns for better readability
    if not df_operators.empty:
        df_operators = df_operators.rename(columns={
            'user__registered_by__name': 'Operator Name',
            'tickets_count': 'Total Tickets',
            'total_amount': 'Total Revenue',
            'gawader_tickets': 'Gawader Tickets',
            'gawader_amount': 'Gawader Revenue',
            'chaman_tickets': 'Chaman Tickets',
            'chaman_amount': 'Chaman Revenue'
        })
    
    # Create a BytesIO buffer
    buffer = io.BytesIO()
    
    # Create Excel writer
    with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
        # Write operators summary to sheet 1
        if not df_operators.empty:
            df_operators.to_excel(writer, sheet_name='Operator Summary', index=False)
            
            # Format the Operator Summary sheet
            workbook = writer.book
            worksheet = writer.sheets['Operator Summary']
            
            # Format currency columns
            money_format = workbook.add_format({'num_format': 'PKR #,##0'})
            for col_num, column in enumerate(df_operators.columns):
                if 'Revenue' in column:
                    worksheet.set_column(col_num, col_num, 18, money_format)
        
        # Write ticket data to sheet 2
        if not df_tickets.empty:
            df_tickets.to_excel(writer, sheet_name='Ticket Details', index=False)
            
            # Format the Ticket Details sheet
            workbook = writer.book
            worksheet = writer.sheets['Ticket Details']
            
            # Format currency columns
            money_format = workbook.add_format({'num_format': 'PKR #,##0'})
            date_format = workbook.add_format({'num_format': 'yyyy-mm-dd hh:mm'})
            
            # Add column formatting
            for col_num, column in enumerate(df_tickets.columns):
                if column == 'Price':
                    worksheet.set_column(col_num, col_num, 12, money_format)
                elif column == 'Created On':
                    worksheet.set_column(col_num, col_num, 20, date_format)
                elif column == 'Ticket ID':
                    worksheet.set_column(col_num, col_num, 40)
                else:
                    worksheet.set_column(col_num, col_num, 18)
        
        # Add summary sheet
        summary_data = {
            'Metric': [
                'Total Tickets',
                'Gawader Tickets',
                'Chaman Tickets',
                'Total Revenue',
                'Gawader Revenue',
                'Chaman Revenue',
                'Report Date Range'
            ],
            'Value': [
                tickets_queryset.count(),
                tickets_queryset.filter(ticket_type=Ticket.GAWADER_ENCLOSURE).count(),
                tickets_queryset.filter(ticket_type=Ticket.CHAMAN_ENCLOSURE).count(),
                tickets_queryset.aggregate(total=Sum('price'))['total'] or 0,
                tickets_queryset.filter(ticket_type=Ticket.GAWADER_ENCLOSURE).aggregate(total=Sum('price'))['total'] or 0,
                tickets_queryset.filter(ticket_type=Ticket.CHAMAN_ENCLOSURE).aggregate(total=Sum('price'))['total'] or 0,
                f"{date_from or 'All'} to {date_to or 'All'}"
            ]
        }
        
        df_summary = pd.DataFrame(summary_data)
        df_summary.to_excel(writer, sheet_name='Summary', index=False)
        
        # Format the Summary sheet
        worksheet = writer.sheets['Summary']
        money_format = workbook.add_format({'num_format': 'PKR #,##0'})
        
        # Format revenue rows
        for row in range(1, 7):
            if 'Revenue' in df_summary.loc[row-1, 'Metric']:
                worksheet.write(row, 1, df_summary.loc[row-1, 'Value'], money_format)
    
    # Set the buffer's position to the beginning
    buffer.seek(0)
    
    # Generate file name with date range
    date_str = ""
    if date_from:
        date_str += f"from_{date_from}"
    if date_to:
        date_str += f"_to_{date_to}"
    
    if not date_str:
        date_str = "all_time"
    
    # Create response
    response = HttpResponse(
        buffer.getvalue(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=IBC_Financial_Report_{date_str}.xlsx'
    
    return response