from rest_framework import serializers
from .models import Ticket, TicketType, Gate, ScanLog
from django.contrib.auth.models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']

class TicketTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = TicketType
        fields = '__all__'

class GateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Gate
        fields = '__all__'

class TicketSerializer(serializers.ModelSerializer):
    ticket_type_details = TicketTypeSerializer(source='ticket_type', read_only=True)
    user_details = UserSerializer(source='user', read_only=True)
    created_by_details = UserSerializer(source='created_by', read_only=True)
    
    class Meta:
        model = Ticket
        fields = '__all__'
        read_only_fields = ['ticket_id', 'qr_code', 'created_at', 'created_by']
    
    def create(self, validated_data):
        request = self.context.get("request")
        validated_data['user'] = request.user
        validated_data['created_by'] = request.user
        return super().create(validated_data)

class ScanLogSerializer(serializers.ModelSerializer):
    ticket_details = TicketSerializer(source='ticket', read_only=True)
    gate_details = GateSerializer(source='gate', read_only=True)
    scanned_by_details = UserSerializer(source='scanned_by', read_only=True)
    
    class Meta:
        model = ScanLog
        fields = '__all__'
        read_only_fields = ['id', 'scanned_at']
    
    def create(self, validated_data):
        request = self.context.get("request")
        validated_data['scanned_by'] = request.user
        return super().create(validated_data)

class TicketScanSerializer(serializers.Serializer):
    ticket_id = serializers.UUIDField()
    gate_id = serializers.IntegerField()
    
    def validate(self, data):
        try:
            # Check if ticket exists
            ticket = Ticket.objects.get(ticket_id=data['ticket_id'])
            data['ticket'] = ticket
            
            # Check if gate exists
            gate = Gate.objects.get(id=data['gate_id'])
            data['gate'] = gate
            
            # Check if ticket is active
            if ticket.status != 'active' and ticket.status != 'used':
                raise serializers.ValidationError(f"Ticket is {ticket.status} and cannot be scanned")
            
            # Check if already scanned at this gate
            if ScanLog.objects.filter(ticket=ticket, gate=gate).exists():
                raise serializers.ValidationError(f"Ticket already scanned at {gate.name}")
            
            # Check if scanned at gate 2 without gate 1
            if gate.name == "Gate 2 (Exit)":
                gate1 = Gate.objects.get(name="Gate 1 (Entry)")
                if not ScanLog.objects.filter(ticket=ticket, gate=gate1).exists():
                    data['tampered'] = True
                else:
                    data['tampered'] = False
            else:
                data['tampered'] = False
                
            return data
            
        except Ticket.DoesNotExist:
            raise serializers.ValidationError("Invalid ticket ID")
        except Gate.DoesNotExist:
            raise serializers.ValidationError("Invalid gate ID")