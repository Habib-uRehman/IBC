import qrcode
import io
from django.core.files.base import ContentFile
from django.db import transaction
from django.utils import timezone
from .models import Ticket, ScanLog, TicketUser
import logging

# Set up logging
logger = logging.getLogger(__name__)

def generate_qr_code(data, ticket_instance):
    """
    Generate a QR code for a ticket
    
    Args:
        data (str): The data to encode in the QR code (typically the ticket ID)
        ticket_instance (Ticket): The ticket object to attach the QR code to
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:

        qr_data = f"T:{ticket_instance.ticket_id}"
        # Or even simpler
        # qr_data = str(ticket_instance.ticket_id)
        
        # Use higher error correction level for better scanning
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,  # Medium error correction
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save to memory first
        buffer = io.BytesIO()
        img.save(buffer)
        buffer.seek(0)
        
        # Save to ticket model
        ticket_instance.qr_code.save(
            f'{ticket_instance.ticket_id}.png',
            ContentFile(buffer.read()),
            save=True
        )
        
        return True
    except Exception as e:
        logger.error(f"Error generating QR code: {str(e)}")
        return False

@transaction.atomic
def process_ticket_scan(ticket_id, gate, scanned_by=None, notes=None):
    """
    Process a ticket scan at a gate
    
    Args:
        ticket_id (UUID): The ID of the ticket being scanned
        gate (str): The gate where the ticket is being scanned (gate1 or gate2)
        scanned_by (User): The user who scanned the ticket
        notes (str): Any additional notes
        
    Returns:
        tuple: (success, message, scan_log)
    """
    try:
        # Get the ticket - Use select_for_update to lock the row
        ticket = Ticket.objects.select_for_update().get(ticket_id=ticket_id)
        
        # Initialize message variable
        message = ""
        
        # Check if the ticket has already been scanned at this gate
        if ScanLog.objects.filter(ticket=ticket, gate=gate).exists():
            return False, f"This ticket has already been scanned at {gate}. Duplicate scan detected!", None
        
        # Process based on gate
        if gate == ScanLog.GATE1:
            # Gate 1 scan - we're good regardless of status
            if ticket.status != Ticket.UNSCANNED:
                # Already scanned previously
                return False, "This ticket has already been processed. Cannot scan again.", None
                
            ticket.status = Ticket.SCANNED_GATE1
            message = "Ticket successfully scanned at Gate 1."
            
        elif gate == ScanLog.GATE2:
            # Gate 2 scan - check if gate 1 was scanned first
            if ticket.status == Ticket.UNSCANNED:
                # Tampering detected - ticket scanned at Gate 2 without Gate 1
                ticket.status = Ticket.TAMPERED
                ticket.is_tampered = True
                message = "WARNING: Ticket scanned at Gate 2 without Gate 1 first! Marked as tampered."
            elif ticket.status == Ticket.SCANNED_GATE1:
                # Normal flow - ticket was scanned at Gate 1 first
                ticket.status = Ticket.SCANNED_BOTH
                message = "Ticket successfully scanned at both gates."
            elif ticket.status == Ticket.SCANNED_BOTH:
                # Already scanned at both gates
                return False, "This ticket has already been scanned at both gates. Cannot scan again.", None
            else:
                # Already tampered
                return False, "This ticket is marked as tampered and cannot be scanned again.", None
        
        # Save the ticket
        ticket.updated_at = timezone.now()
        ticket.save()
        
        # Create a scan log
        scan_log = ScanLog.objects.create(
            ticket=ticket,
            gate=gate,
            scanned_by=scanned_by,
            notes=notes
        )
        
        return True, message, scan_log
    
    except Ticket.DoesNotExist:
        return False, "Invalid ticket ID. Ticket not found.", None
    
    except Exception as e:
        logger.error(f"Error processing ticket scan: {str(e)}")
        return False, f"Error processing scan: {str(e)}", None

    
def get_dashboard_stats():
    """
    Get statistics for the dashboard
    
    Returns:
        dict: Dictionary containing dashboard statistics
    """
    from django.db.models import Count
    
    # Get total counts
    total_users = TicketUser.objects.count()
    total_tickets = Ticket.objects.count()
    scanned_tickets = Ticket.objects.exclude(status=Ticket.UNSCANNED).count()
    
    # Get gender distribution
    male_tickets = Ticket.objects.filter(user__gender=TicketUser.MALE).count()
    female_tickets = Ticket.objects.filter(user__gender=TicketUser.FEMALE).count()
    
    # Get ticket status counts
    unscanned_count = Ticket.objects.filter(status=Ticket.UNSCANNED).count()
    scanned_gate1_count = Ticket.objects.filter(status=Ticket.SCANNED_GATE1).count()
    scanned_both_count = Ticket.objects.filter(status=Ticket.SCANNED_BOTH).count()
    tampered_count = Ticket.objects.filter(status=Ticket.TAMPERED).count()
    
    # Get ticket type counts
    gawader_count = Ticket.objects.filter(ticket_type=Ticket.GAWADER_ENCLOSURE).count()
    chaman_count = Ticket.objects.filter(ticket_type=Ticket.CHAMAN_ENCLOSURE).count()
    
    # Calculate daily registrations for the past week
    from django.utils import timezone
    import datetime
    
    today = timezone.now().date()
    week_ago = today - datetime.timedelta(days=7)
    
    daily_registrations = {}
    for i in range(7):
        date = week_ago + datetime.timedelta(days=i+1)
        count = Ticket.objects.filter(created_at__date=date).count()
        daily_registrations[date.strftime('%Y-%m-%d')] = count
    
    # Get latest scan activities
    recent_scans = ScanLog.objects.order_by('-scanned_at')[:10]
    
    # Get recent users
    recent_users = TicketUser.objects.order_by('-created_at')[:10]
    
    return {
        'total_users': total_users,
        'total_tickets': total_tickets,
        'scanned_tickets': scanned_tickets,
        'male_tickets': male_tickets,
        'female_tickets': female_tickets,
        'unscanned_count': unscanned_count,
        'scanned_gate1_count': scanned_gate1_count,
        'scanned_both_count': scanned_both_count,
        'tampered_count': tampered_count,
        'gawader_count': gawader_count,
        'chaman_count': chaman_count,
        'daily_registrations': daily_registrations,
        'recent_scans': recent_scans,
        'recent_users': recent_users,
    }

def export_tickets_to_csv(queryset):
    """
    Export tickets to CSV
    
    Args:
        queryset: QuerySet of Ticket objects
        
    Returns:
        str: CSV content
    """
    import csv
    from io import StringIO
    
    csv_buffer = StringIO()
    writer = csv.writer(csv_buffer)
    
    # Write header
    writer.writerow([
        'Ticket ID',
        'User Name',
        'Father Name',
        'Email',
        'Phone',
        'CNIC',
        'Gender',
        'Age',
        'Ticket Type',
        'Price',
        'Status',
        'Created Date',
        'Gate 1 Scan',
        'Gate 2 Scan',
    ])
    
    # Write data
    for ticket in queryset:
        # Get gate scan timestamps
        gate1_scan = ticket.scan_logs.filter(gate=ScanLog.GATE1).first()
        gate2_scan = ticket.scan_logs.filter(gate=ScanLog.GATE2).first()
        
        writer.writerow([
            ticket.ticket_id,
            ticket.user.full_name,
            ticket.user.father_name,
            ticket.user.email,
            ticket.user.phone_number,
            ticket.user.cnic_number,
            ticket.user.get_gender_display(),
            ticket.user.age,
            ticket.get_ticket_type_display(),
            ticket.price,
            ticket.get_status_display(),
            ticket.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            gate1_scan.scanned_at.strftime('%Y-%m-%d %H:%M:%S') if gate1_scan else 'Not Scanned',
            gate2_scan.scanned_at.strftime('%Y-%m-%d %H:%M:%S') if gate2_scan else 'Not Scanned',
        ])
    
    return csv_buffer.getvalue()