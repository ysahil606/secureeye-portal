from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List

from database import get_db
from models import MediaItem
from schemas import MediaItemOut

router = APIRouter(prefix="/media", tags=["Media Hub"])

@router.get("/", response_model=List[MediaItemOut])
def get_media_items(db: Session = Depends(get_db)):
    """
    Returns all media items sorted by newest first.
    The frontend can group them by 'media_type'.
    """
    return db.query(MediaItem).order_by(desc(MediaItem.published_at)).limit(100).all()
