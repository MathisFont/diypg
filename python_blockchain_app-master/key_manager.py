from key_events import KeyEventType

# Gère le cycle de vie des clés cryptographiques dans la blockchain
class KeyManager:
    
    # Récupère l'historique complet des événements de clés pour un email
    @staticmethod 
    def get_key_history(email, blockchain):
        history = []
        for block in blockchain.chain:
            for transaction in block.transactions:
                content = transaction.get("content", {})
                if isinstance(content, dict) and content.get("email") == email:
                    history.append(content)
        return history

    # Détermine si une clé est valide en analysant son historique
    @staticmethod
    def is_key_valid(key, email, blockchain):
        history = KeyManager.get_key_history(email, blockchain)
        
        key_status = False
        for event in sorted(history, key=lambda x: x["timestamp"]):
            if event["key"] == key:
                if event["event_type"] in [KeyEventType.NCK.value, KeyEventType.NSK.value]:
                    key_status = True
                elif event["event_type"] in [KeyEventType.RCK.value, KeyEventType.RSK.value]:
                    key_status = False
        
        return key_status