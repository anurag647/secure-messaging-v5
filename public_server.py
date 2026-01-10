"""
Public Server with Ngrok Tunnel
Run this to expose your Secure Messaging app to the internet
"""
from pyngrok import ngrok
import subprocess
import sys
import time

print("\n" + "="*60)
print("   SECURE MESSAGING v5.0 - PUBLIC SERVER")
print("="*60)

# Start ngrok tunnel
print("\n[*] Starting ngrok tunnel...")
try:
    # Connect to ngrok
    public_url = ngrok.connect(5000)
    print(f"\n[SUCCESS] Your app is now PUBLIC!")
    print(f"\n" + "="*60)
    print(f"   PUBLIC URL: {public_url}")
    print("="*60)
    print(f"\n   Share this link with anyone to access your app!")
    print(f"   Local URL: http://127.0.0.1:5000")
    print("\n   Press Ctrl+C to stop the server")
    print("="*60 + "\n")
    
    # Start Flask server
    subprocess.run([sys.executable, "server.py"])
    
except KeyboardInterrupt:
    print("\n[*] Shutting down...")
    ngrok.kill()
except Exception as e:
    print(f"\n[ERROR] {e}")
    print("\nTo use ngrok, you need to sign up at https://ngrok.com")
    print("Then run: ngrok config add-authtoken YOUR_TOKEN")
