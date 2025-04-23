from django import forms
from .models import TicketUser, Ticket, ScanLog
from .models import TicketQuota
import uuid

class TicketUserForm(forms.ModelForm):
    """Form for registering new ticket users"""
    
    class Meta:
        model = TicketUser
        fields = ['full_name', 'father_name', 'email', 'phone_number', 
                  'cnic_number', 'related_to', 'relationship',
                  'gender', 'age', 'profile_picture']
        widgets = {
            'gender': forms.Select(attrs={'class': 'form-control'}),
            'relationship': forms.Select(attrs={'class': 'form-control'}),
            'age': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter age'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add Bootstrap classes to form inputs
        for field_name, field in self.fields.items():
            if field.widget.__class__.__name__ != 'CheckboxInput':
                field.widget.attrs['class'] = 'form-control'
                field.widget.attrs['placeholder'] = f'Enter {field_name.replace("_", " ")}'
        
        # Make 'related_to' initially hidden, shown with JavaScript
        self.fields['related_to'].widget.attrs.update({
            'class': 'form-control related-to-field',
            'placeholder': 'Enter name of primary CNIC holder',
        })
    
    def clean_cnic_number(self):
        """
        Custom validation for CNIC number that allows duplicates 
        when relationship is not 'self'
        """
        cnic_number = self.cleaned_data.get('cnic_number')
        relationship = self.cleaned_data.get('relationship')
        
        # Only check uniqueness if this is a primary user (relationship = 'self')
        if relationship == 'self':
            # Check if another primary user has this CNIC
            if TicketUser.objects.filter(
                cnic_number=cnic_number, 
                relationship='self'
            ).exists():
                raise forms.ValidationError("This CNIC is already registered as a primary user.")
        
        return cnic_number

class TicketForm(forms.ModelForm):
    """Form for generating tickets"""
    
    class Meta:
        model = Ticket
        fields = ['ticket_type']
        widgets = {
            'ticket_type': forms.Select(attrs={'class': 'form-control'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Update ticket type choices to show remaining tickets
        choices = []
        for ticket_type, label in self.fields['ticket_type'].choices:
            if ticket_type and ticket_type in dict(Ticket.TICKET_TYPES):
                try:
                    quota = TicketQuota.objects.get(ticket_type=ticket_type)
                    if quota.remaining > 0:
                        choices.append((ticket_type, f"{label} - {quota.remaining} available"))
                    else:
                        choices.append((ticket_type, f"{label} - SOLD OUT"))
                except TicketQuota.DoesNotExist:
                    choices.append((ticket_type, label))
            else:
                choices.append((ticket_type, label))
        
        self.fields['ticket_type'].choices = choices
    
    def clean_ticket_type(self):
        """Validate that tickets are available for the selected type"""
        ticket_type = self.cleaned_data.get('ticket_type')
        
        try:
            quota = TicketQuota.objects.get(ticket_type=ticket_type)
            if quota.remaining <= 0:
                raise forms.ValidationError(f"Sorry, no more tickets available for {ticket_type}.")
        except TicketQuota.DoesNotExist:
            pass
            
        return ticket_type


class ScanTicketForm(forms.Form):
    """Form for scanning tickets at gates"""
    
    ticket_id = forms.CharField(
        widget=forms.TextInput(
            attrs={
                'class': 'form-control',
                'placeholder': 'Scan or enter ticket ID',
                'id': 'ticket_id'
            }
        )
    )
    
    gate = forms.ChoiceField(
        choices=[('gate1', 'Gate 1 (Entry)'), ('gate2', 'Gate 2 (Exit)')],
        widget=forms.Select(attrs={'class': 'form-control', 'id': 'gate_id'})
    )
    
    notes = forms.CharField(
        required=False,
        widget=forms.Textarea(
            attrs={
                'class': 'form-control',
                'placeholder': 'Optional notes',
                'rows': 2
            }
        )
    )
    
    def clean_ticket_id(self):
        """Clean and convert the ticket ID to a proper UUID"""
        ticket_id = self.cleaned_data.get('ticket_id')
        if not ticket_id:
            raise forms.ValidationError("Ticket ID is required")
        
        # Remove any whitespace, dashes, or other common scanner artifacts
        ticket_id = ticket_id.strip().replace(' ', '')
        
        # Remove T: prefix if present (from scanner)
        if ticket_id.startswith("T:"):
            ticket_id = ticket_id[2:]
        
        # Try direct conversion
        try:
            return uuid.UUID(ticket_id)
        except ValueError:
            try:
                # Try with dashes added at standard positions
                if len(ticket_id) == 32:
                    formatted_id = f"{ticket_id[0:8]}-{ticket_id[8:12]}-{ticket_id[12:16]}-{ticket_id[16:20]}-{ticket_id[20:]}"
                    return uuid.UUID(formatted_id)
            except ValueError:
                pass
            
            # If still not valid, try to extract UUID pattern from the string
            import re
            uuid_pattern = re.compile(r'[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}', re.IGNORECASE)
            match = uuid_pattern.search(ticket_id)
            if match:
                try:
                    return uuid.UUID(match.group(0))
                except ValueError:
                    pass
        
        raise forms.ValidationError("Enter a valid UUID.")

class QuotaForm(forms.ModelForm):
    """Form for managing ticket quotas"""
    
    class Meta:
        model = TicketQuota
        fields = ['total_quantity']
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        if self.instance and self.instance.pk:
            self.fields['total_quantity'].help_text = f"Currently sold: {self.instance.sold_quantity}"
            
    def clean_total_quantity(self):
        """Validate the total quantity isn't less than already sold tickets"""
        total = self.cleaned_data.get('total_quantity')
        
        if self.instance and self.instance.pk and total < self.instance.sold_quantity:
            raise forms.ValidationError(
                f"Total cannot be less than already sold tickets ({self.instance.sold_quantity})"
            )
            
        return total

class TicketSearchForm(forms.Form):
    """Form for searching and filtering tickets"""
    
    GENDER_CHOICES = [('', 'All Gender')] + list(TicketUser.GENDER_CHOICES)
    STATUS_CHOICES = [('', 'All Status')] + list(Ticket.STATUS_CHOICES)
    
    gender = forms.ChoiceField(
        choices=GENDER_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    status = forms.ChoiceField(
        choices=STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'})
    )
    
    search = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control',
                'placeholder': 'Search users or tickets...'
            }
        )
    )

class ReportForm(forms.Form):
    """Form for generating reports"""
    
    REPORT_TYPES = [
        ('all_tickets', 'All Tickets'),
        ('scanned_tickets', 'Scanned Tickets'),
        ('unscanned_tickets', 'Unscanned Tickets'),
        ('tampered_tickets', 'Tampered Tickets'),
    ]
    
    REPORT_FORMATS = [
        ('pdf', 'PDF'),
        ('csv', 'CSV'),
    ]
    
    report_type = forms.ChoiceField(
        choices=REPORT_TYPES,
        widget=forms.Select(attrs={'class': 'form-control', 'id': 'report_type'})
    )
    
    report_format = forms.ChoiceField(
        choices=REPORT_FORMATS,
        widget=forms.Select(attrs={'class': 'form-control', 'id': 'report_format'})
    )
    
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date', 'id': 'date_from'})
    )
    
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date', 'id': 'date_to'})
    )