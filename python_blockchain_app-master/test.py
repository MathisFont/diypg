import requests
import json
from datetime import datetime

# URL du serveur blockchain
BASE_URL = "http://localhost:8000"

# Affiche un séparateur visuel dans les logs
def print_separator():
    print("\n" + "="*50 + "\n")

# Vérifie le statut d'une clé (valide/révoquée)
def verify_key_status(key, email, expected_status):
    data = {
        "key": key,
        "email": email
    }
    response = requests.post(f"{BASE_URL}/verify_key", json=data)
    result = response.json()['valid']
    print(f"Key verification for {key}: {'valid' if result else 'invalid'}")
    assert result == expected_status, f"Expected key status to be {expected_status}, but got {result}"

# Test la création d'une nouvelle clé de chiffrement
def test_new_key():
    print("Testing new cryptographic key submission...")
    data = {
        "event_type": "NCK",
        "key": "RSA-2048-PUBLIC-KEY-ABC123",
        "email": "test@example.com",
        "public_keys": []
    }
    
    response = requests.post(f"{BASE_URL}/submit_key_event", json=data)
    print("New key response:", response.status_code)
    assert response.status_code == 201

    response = requests.get(f"{BASE_URL}/mine")
    print("Mining response:", response.status_code)
    assert response.status_code == 200
    
    verify_key_status(data["key"], data["email"], True)

# Test la création d'une nouvelle clé de signature
def test_sign_key():
    print("Testing new signing key submission...")
    data = {
        "event_type": "NSK",
        "key": "RSA-2048-SIGN-KEY-XYZ789",
        "email": "test@example.com",
        "public_keys": ["RSA-2048-PUBLIC-KEY-ABC123"]  # Reference to the cryptographic key
    }
    response = requests.post(f"{BASE_URL}/submit_key_event", json=data)
    print("Sign key response:", response.status_code)
    assert response.status_code == 201

    response = requests.get(f"{BASE_URL}/mine")
    assert response.status_code == 200
    
    verify_key_status(data["key"], data["email"], True)

# Test la révocation d'une clé de chiffrement
def test_revoke_key():
    print("Testing key revocation...")
    data = {
        "event_type": "RCK",
        "key": "RSA-2048-PUBLIC-KEY-ABC123",
        "email": "test@example.com"
    }
    
    response = requests.post(f"{BASE_URL}/submit_key_event", json=data)
    print("Revoke key response:", response.status_code)
    assert response.status_code == 201
    
    response = requests.get(f"{BASE_URL}/mine")
    assert response.status_code == 200
    
    verify_key_status(data["key"], data["email"], False)

# Test la révocation d'une clé de signature
def test_revoke_sign_key():
    print("Testing sign key revocation...")
    data = {
        "event_type": "RSK",
        "key": "RSA-2048-SIGN-KEY-XYZ789",
        "email": "test@example.com"
    }
    response = requests.post(f"{BASE_URL}/submit_key_event", json=data)
    print("Revoke sign key response:", response.status_code)
    assert response.status_code == 201
    
    response = requests.get(f"{BASE_URL}/mine")
    assert response.status_code == 200
    
    verify_key_status(data["key"], data["email"], False)

# Test la gestion des événements de clé invalides
def test_invalid_key_event():
    print("Testing invalid key event...")
    data = {
        "event_type": "INVALID",
        "key": "TEST-KEY",
        "email": "test@example.com"
    }
    response = requests.post(f"{BASE_URL}/submit_key_event", json=data)
    print(f"Invalid event response: {response.status_code}")
    print(f"Response content: {response.text}")
    assert response.status_code == 400, f"Expected 400 status code, got {response.status_code}"
    print("Invalid event test passed: received expected 400 Bad Request")

# Affiche l'historique complet des clés d'un utilisateur
def print_full_history():
    print("\nFull key history:")
    response = requests.get(f"{BASE_URL}/key_history/test@example.com")
    history = response.json()
    print(json.dumps(history, indent=2))

# Réinitialise la blockchain à son état initial
def reset_blockchain():
    response = requests.post(f"{BASE_URL}/reset")
    assert response.status_code == 200, "Failed to reset blockchain"
    print("Blockchain reset successful")

if __name__ == "__main__":
    print_separator()
    reset_blockchain()
    
    print_separator()
    test_new_key()
    
    print_separator()
    test_sign_key()
    
    print_separator()
    test_revoke_key()
    
    print_separator()
    test_revoke_sign_key()
    
    print_separator()
    test_invalid_key_event()
    
    print_separator()
    print_full_history()
    print_separator()