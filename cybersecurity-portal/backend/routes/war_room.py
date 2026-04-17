from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session
from typing import List
import os
import shutil
from database import get_db
from models import WarRoomMessage, WarRoomEvidence, Advisory, User
from auth import get_current_active_user

router = APIRouter(prefix="/war-room", tags=["Incident War Room"])

UPLOAD_DIR = "uploads/evidence"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@router.get("/{advisory_id}/messages")
async def get_messages(
    advisory_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    return db.query(WarRoomMessage).filter(
        WarRoomMessage.advisory_id == advisory_id
    ).order_by(WarRoomMessage.created_at.asc()).all()

@router.post("/{advisory_id}/messages")
async def send_message(
    advisory_id: int,
    content: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    msg = WarRoomMessage(advisory_id=advisory_id, user_id=current_user.id, content=content)
    db.add(msg)
    db.commit()
    db.refresh(msg)
    return msg

@router.get("/{advisory_id}/evidence")
async def get_evidence(
    advisory_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    return db.query(WarRoomEvidence).filter(
        WarRoomEvidence.advisory_id == advisory_id
    ).all()

@router.post("/{advisory_id}/evidence")
async def upload_evidence(
    advisory_id: int,
    file: UploadFile = File(...),
    description: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    path = os.path.join(UPLOAD_DIR, f"{advisory_id}_{file.filename}")
    with open(path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    ev = WarRoomEvidence(
        advisory_id=advisory_id,
        user_id=current_user.id,
        file_name=file.filename,
        file_path=path,
        file_type=file.content_type,
        description=description
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev
