"""Quick test to verify Groq API key is valid and working."""
import os, sys

from dotenv import load_dotenv
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

print("[CHECK] GROQ_API_KEY loaded:", "YES [OK]" if GROQ_API_KEY else "NO [MISSING]")
print("[CHECK] Key prefix:", GROQ_API_KEY[:12] + "...")

if not GROQ_API_KEY:
    print("\n[ERROR] No Groq API key found in .env file!")
    sys.exit(1)

try:
    from groq import Groq
    client = Groq(api_key=GROQ_API_KEY)
    print("\n[TEST] Sending test prompt to Groq llama-3.3-70b-versatile...")
    response = client.chat.completions.create(
        messages=[{"role": "user", "content": "Say 'SecureEye Groq connection successful!' and nothing else."}],
        model="llama-3.3-70b-versatile",
        max_tokens=50,
    )
    result = response.choices[0].message.content
    print("\n[RESPONSE]", result)
    print("\n[INFO] Tokens used - Prompt:", response.usage.prompt_tokens, "| Completion:", response.usage.completion_tokens)
    print("\n[SUCCESS] Groq is working! All AI features in SecureEye will use Llama-3.")
except Exception as e:
    print("\n[ERROR] Groq test failed:", e)
    sys.exit(1)
