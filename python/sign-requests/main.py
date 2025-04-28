from datetime import datetime
from typing import Union
import base64
import hashlib
import os
import requests
import time
import uuid

from http_message_signatures import HTTPMessageSigner, HTTPSignatureKeyResolver, algorithms
from cryptography.hazmat.primitives import serialization

# Griffin API endpoint for verifying message signatures
VERIFY_URL = "https://api.griffin.com/v0/security/message-signature/verify"

class GriffinKeyResolver(HTTPSignatureKeyResolver):
    """Key resolver for Griffin HTTP message signatures."""
    
    def __init__(self, private_key_path: str = None):
        """Initialize with a private key from a file or environment variable."""
        private_key_pem = None
        
        # Try to load private key from file first
        if private_key_path and os.path.exists(private_key_path):
            with open(private_key_path, 'rb') as f:
                private_key_pem = f.read()
            print(f"Loaded private key from file: {private_key_path}")
        
        # If not found, try environment variable
        if not private_key_pem:
            env_key = os.getenv('GRIFFIN_PRIVATE_KEY', '')
            if env_key:
                private_key_pem = env_key.encode()
                print("Loaded private key from environment variable")
            else:
                raise ValueError("No private key found. Please provide a private key file or set GRIFFIN_PRIVATE_KEY environment variable.")
        
        # Parse the private key
        try:
            self.private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        except Exception as e:
            raise ValueError(f"Failed to load private key: {str(e)}")
        
        # Get the public key from the private key
        self.public_key = self.private_key.public_key()
        
        # Display public key info for verification
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(f"Successfully loaded Ed25519 key pair. Public key hash: {hash(public_key_pem)}")


    def resolve_public_key(self, key_id: str):
        """Return the public key for verification."""
        return self.public_key

    def resolve_private_key(self, key_id: str):
        """Return the private key for signing."""
        return self.private_key

def generate_content_digest(body: Union[bytes, str]) -> str:
    """Create a SHA-512 digest of the request body."""
    hash_obj = hashlib.sha512(body.encode() if isinstance(body, str) else body)
    encoded = base64.b64encode(hash_obj.digest()).decode()
    return f"sha-512=:{encoded}:"

def main():
    # Load API credentials from environment
    api_key = os.getenv('GRIFFIN_API_KEY')
    if not api_key:
        print("Please set the GRIFFIN_API_KEY environment variable")
        return
    
    key_id = os.getenv('GRIFFIN_KEY_ID')
    if not key_id:
        print("Please set the GRIFFIN_KEY_ID environment variable")
        return
    
    private_key_path = os.getenv('GRIFFIN_PRIVATE_KEY_PATH', 'private_key.pem')
    
    # Create key resolver
    key_resolver = GriffinKeyResolver(private_key_path)
    
    # Request body
    body = '{"hello": "world"}'
    
    # Generate unique nonce for this request
    nonce = str(uuid.uuid4())
    
    # Get current time for created parameter
    created = datetime.fromtimestamp(time.time())
    
    # The date format is arbitrary. Not verified.
    time_now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

    # Prepare request headers
    headers = {
        "Host": "api.griffin.com",
        "Date": time_now,
        "Content-Type": "application/json",
        "Authorization": f"GriffinAPIKey {api_key}"
    }
    
    # Create request
    request = requests.Request("POST", VERIFY_URL, data=body, headers=headers)
    prepared_request = request.prepare()
    
    # Calculate and add Content-Digest
    content_digest = generate_content_digest(body)
    prepared_request.headers["Content-Digest"] = content_digest
    
    # Sign the request
    signer = HTTPMessageSigner(signature_algorithm=algorithms.ED25519, key_resolver=key_resolver)
    signer.sign(
        prepared_request, 
        key_id=key_id, 
        label="sig1", 
        nonce=nonce, 
        include_alg=False, 
        created=created, 
        covered_component_ids=(
            "@method", "@authority", "@path", "content-type", 
            "content-length", "date", "content-digest", "@query"
        )
    )
    
    # Print the signed request details for debugging
    print("\nSigned Headers:")
    for header, value in prepared_request.headers.items():
        print(f"{header}: {value}")
    
    # Send the request to Griffin
    print(f"\nSending request to {VERIFY_URL}")
    response = requests.Session().send(prepared_request)
    
    # Print the response
    print(f"\nStatus Code: {response.status_code}")
    print("\nResponse Body:")
    print(response.text)
    
    # Show response headers for debugging
    print("\nResponse Headers:")
    for header, value in response.headers.items():
        print(f"{header}: {value}")

if __name__ == "__main__":
    main()