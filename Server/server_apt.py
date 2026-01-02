#AETHER C2 FRAMEWORK - SERVER
#Author: Andrei Costin
#License: MIT (Educational use only)
#Decryption logic is abstracted for public release.


import logging
import os
import threading
import time
from flask import Flask, request
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#CONFIGURATION
BIND_IP = "0.0.0.0" 
PORT = 8080

# GLOBAL STATE
CURRENT_TASK = None 
WAITING_FOR_RESULT = False
SESSIONS = {} 

#FLASK SETUP
app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR) 

#CRYPTO HELPERS
def load_server_keys():
    """Loads ECC keys. Requires manual generation for security."""
    if not os.path.exists("server_priv.pem"):
        raise FileNotFoundError("[ :)) ] CRITICAL: 'server_priv.pem' missing. Generate keys manually to enable C2.")
    
    with open("server_priv.pem", "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    return priv

try:
    SERVER_PRIV_KEY = load_server_keys()
    SERVER_PUB_KEY = SERVER_PRIV_KEY.public_key()
except Exception as e:
    print(f"[!] SETUP ERROR: {e}")
    print("[*] The server cannot start without valid cryptographic identity.")
    exit(1)

#CORE LOGIC
@app.route('/api/v6/sync', methods=['POST'])
def sync():
    global CURRENT_TASK, WAITING_FOR_RESULT
    try:
        data = request.get_data()
        if len(data) < 21: return ""
        msg_type = data[0]
        
        #HANDSHAKE
        if msg_type == 0x01:
            agent_id = data[1:17].hex()
            client_pub_bytes = data[21:]
            
            #ECDH SI HKDF
            client_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub_bytes)
            shared = SERVER_PRIV_KEY.exchange(ec.ECDH(), client_pub)
            aes_key = HKDF(hashes.SHA256(), 32, None, b"aether-v6-binary").derive(shared)
            SESSIONS[agent_id] = aes_key
            
            return SERVER_PUB_KEY.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)

        #BEACON
        elif msg_type == 0x02:
            agent_id = data[1:17].hex()
            if agent_id not in SESSIONS: return b'\x00'
            
            #Parsing payload
            payload = data[29:]
            nonce = payload[:12]
            ciphertext = payload[12:]
            seq_bytes = data[17:25]
            aad = bytes.fromhex(agent_id) + seq_bytes
            
            #SECURITY TO PREVENT MISUSE
            # An authorized researcher knows how to implement: AESGCM(key).decrypt(nonce, ciphertext, aad)
            
            #START REDACTED BLOCK
            # plaintext = aes_decrypt_wrapper(SESSIONS[agent_id], nonce, ciphertext, aad)
            raise NotImplementedError("Decryption logic redacted for public release.  :)))) ")
            #END REDACTED BLOCK

            #Logic below would process the 'plaintext' variable...
            #msg = plaintext.decode()
            #if msg == "PING": ... 

    except NotImplementedError:
        print(f" BLOCKED: Someone tried to use the C2 without implementing decryption.")
        return b""
    except Exception:
        pass
    return ""

#CONSOLE UI
def console_loop():
    print("\n[*] C2 INTERACTIVE CONSOLE")
    print("[*] STATUS: LISTENING")
    while True:
        input("C2 (SafeMode)> ")

if __name__ == '__main__':
    t = threading.Thread(target=app.run, kwargs={'host':BIND_IP, 'port':PORT}, daemon=True)
    t.start()
    console_loop()