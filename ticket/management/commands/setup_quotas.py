from django.core.management.base import BaseCommand
from ticket.models import TicketQuota, Ticket

class Command(BaseCommand):
    help = 'Sets up initial ticket quotas'

    def add_arguments(self, parser):
        # Optional arguments
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Reset sold quantities to zero',
        )

    def handle(self, *args, **options):
        # Create quota for Gawader Enclosure
        gawader_quota, created = TicketQuota.objects.update_or_create(
            ticket_type=Ticket.GAWADER_ENCLOSURE,
            defaults={'total_quantity': 1750}
        )
        
        # Create quota for Chaman Enclosure
        chaman_quota, created = TicketQuota.objects.update_or_create(
            ticket_type=Ticket.CHAMAN_ENCLOSURE,
            defaults={'total_quantity': 1750}
        )
        
        # Reset sold quantities if requested
        if options['reset']:
            gawader_quota.sold_quantity = 0
            gawader_quota.save()
            
            chaman_quota.sold_quantity = 0
            chaman_quota.save()
            
            self.stdout.write(self.style.SUCCESS('Reset sold quantities to zero'))
        else:
            # Update sold quantities to match actual tickets
            gawader_count = Ticket.objects.filter(ticket_type=Ticket.GAWADER_ENCLOSURE).count()
            chaman_count = Ticket.objects.filter(ticket_type=Ticket.CHAMAN_ENCLOSURE).count()
            
            gawader_quota.sold_quantity = gawader_count
            gawader_quota.save()
            
            chaman_quota.sold_quantity = chaman_count
            chaman_quota.save()
            
            self.stdout.write(self.style.SUCCESS(f'Updated sold quantities: Gawader={gawader_count}, Chaman={chaman_count}'))
        
        self.stdout.write(self.style.SUCCESS('Successfully set up ticket quotas'))
        self.stdout.write(self.style.SUCCESS(f'Gawader Enclosure: {gawader_quota.remaining} remaining'))
        self.stdout.write(self.style.SUCCESS(f'Chaman Enclosure: {chaman_quota.remaining} remaining'))
