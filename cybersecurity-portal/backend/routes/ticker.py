from fastapi import APIRouter
from services.ticker_service import get_ticker_bytes

router = APIRouter(prefix="/ticker", tags=["Matrix Ticker"])

@router.get("/")
def get_ticker_data():
    """
    Returns the latest cached ticker bytes from live intelligence sources.
    """
    bytes_data = get_ticker_bytes()
    return {"ticker_bytes": bytes_data}
