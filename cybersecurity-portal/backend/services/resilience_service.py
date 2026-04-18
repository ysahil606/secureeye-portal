import logging
import google.generativeai as genai
from config import settings

logger = logging.getLogger("resilience")

async def diagnose_error_with_ai(error_log: str, context: str = ""):
    """
    Uses Gemini AI to diagnose a system error and suggest a resolution.
    """
    if not settings.GEMINI_API_KEY:
        return "AI Diagnosis unavailable: Missing API Key."

    try:
        genai.configure(api_key=settings.GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = f"""
        You are the Secure Portal Self-Healing Engine. 
        Analyze the following system error and provide a 3-line concise recovery plan.
        
        ERROR LOG:
        {error_log}
        
        SYSTEM CONTEXT:
        {context}
        
        RESPONSE FORMAT:
        1. Root Cause: (Identification)
        2. Immediate Fix: (How to resolve right now)
        3. Prevention: (How to stop it happening again)
        """
        
        response = await model.generate_content_async(prompt)
        return response.text
    except Exception as e:
        logger.error(f"AI Diagnosis failed: {e}")
        return "Resilience Engine encountered an internal error during diagnosis."
