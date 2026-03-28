from enum import Enum
from datetime import datetime

# Types d'événements possibles pour la gestion des clés
class KeyEventType(Enum):
    NCK = "NCK"  # New Cryptographic Key
    RCK = "RCK"  # Revoke Cryptographic Key
    NSK = "NSK"  # New Sign Key
    RSK = "RSK"  # Revoke Sign Key

# Représente un événement de gestion de clé dans la blockchain
class KeyEvent:
    # Crée un nouvel événement de clé
    def __init__(self, event_type, key, email, public_keys=None):
        self.timestamp = datetime.now().isoformat()
        self.event_type = event_type
        self.key = key
        self.email = email
        self.public_keys = public_keys if public_keys else []

    # Convertit l'événement en dictionnaire pour la sérialisation
    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "key": self.key,
            "email": self.email,
            "public_keys": self.public_keys
        }

    # Crée un événement à partir d'un dictionnaire
    @classmethod
    def from_dict(cls, data):
        event = cls(
            KeyEventType(data["event_type"]),
            data["key"],
            data["email"],
            data.get("public_keys", [])
        )
        event.timestamp = data["timestamp"]
        return event