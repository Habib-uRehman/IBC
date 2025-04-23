from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from ticket.models import Operator
import getpass
import csv
import os

class Command(BaseCommand):
    help = 'Creates new operator accounts for the ticketing system'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, help='Username for the operator')
        parser.add_argument('--name', type=str, help='Full name of the operator')
        parser.add_argument('--location', type=str, help='Location where operator is based')
        parser.add_argument('--contact', type=str, help='Contact number for the operator')
        parser.add_argument('--batch', action='store_true', help='Create multiple operators from a CSV file')
        parser.add_argument('--csv', type=str, help='Path to CSV file with operator details')

    def handle(self, *args, **options):
        if options['batch'] and options['csv']:
            self.create_batch_operators(options['csv'])
        else:
            self.create_single_operator(options)
    
    def create_single_operator(self, options):
        username = options['username']
        if not username:
            username = input("Enter username for operator: ")
        
        name = options['name']
        if not name:
            name = input("Enter full name of operator: ")
        
        location = options['location']
        if not location:
            location = input("Enter location for operator: ")
        
        contact = options['contact']
        if not contact:
            contact = input("Enter contact number (optional): ")
        
        # Get password securely
        password = getpass.getpass("Enter password for operator: ")
        password_confirm = getpass.getpass("Confirm password: ")
        
        if password != password_confirm:
            raise CommandError("Passwords do not match")
        
        try:
            # Check if user already exists
            if User.objects.filter(username=username).exists():
                raise CommandError(f"User with username '{username}' already exists")
                
            # Create the auth user
            user = User.objects.create_user(
                username=username,
                password=password,
                is_staff=False,
                is_superuser=False
            )
            
            # Create the operator profile
            operator = Operator.objects.create(
                user=user,
                name=name,
                location=location,
                contact_number=contact,
                is_active=True
            )
            
            self.stdout.write(self.style.SUCCESS(f"Successfully created operator '{name}' at {location}"))
            return operator
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error creating operator: {str(e)}"))
            
    def create_batch_operators(self, csv_path):
        if not os.path.exists(csv_path):
            raise CommandError(f"CSV file not found: {csv_path}")
            
        try:
            with open(csv_path, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                successful = 0
                failed = 0
                
                for row in reader:
                    try:
                        # Check for required fields
                        if not all(k in row for k in ['username', 'name', 'location', 'password']):
                            self.stdout.write(self.style.WARNING(
                                f"Skipping row: Missing required fields. Required: username, name, location, password"
                            ))
                            failed += 1
                            continue
                            
                        # Check if user already exists
                        if User.objects.filter(username=row['username']).exists():
                            self.stdout.write(self.style.WARNING(
                                f"Skipping: User with username '{row['username']}' already exists"
                            ))
                            failed += 1
                            continue
                            
                        # Create user and operator
                        user = User.objects.create_user(
                            username=row['username'],
                            password=row['password'],
                            is_staff=False,
                            is_superuser=False
                        )
                        
                        operator = Operator.objects.create(
                            user=user,
                            name=row['name'],
                            location=row['location'],
                            contact_number=row.get('contact', ''),
                            is_active=True
                        )
                        
                        successful += 1
                        self.stdout.write(self.style.SUCCESS(
                            f"Created operator: {row['name']} at {row['location']}"
                        ))
                        
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(
                            f"Error creating operator {row.get('name', row.get('username', 'unknown'))}: {str(e)}"
                        ))
                        failed += 1
                
                self.stdout.write(self.style.SUCCESS(
                    f"Batch import completed: {successful} operators created, {failed} failed"
                ))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error reading CSV file: {str(e)}"))