from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from database import get_db
from models import Advisory, AdvisoryAnnotation, AnalystTask, User, UserRole
from auth import get_current_active_user, require_role
from schemas import AnnotationCreate, AnnotationOut, TaskCreate, TaskOut

router = APIRouter(tags=["Collaboration"])


@router.get("/advisories/{advisory_id}/annotations", response_model=List[AnnotationOut])
async def get_annotations(
    advisory_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    adv = db.query(Advisory).filter(Advisory.id == advisory_id).first()
    if not adv:
        raise HTTPException(status_code=404, detail="Advisory not found")
    return db.query(AdvisoryAnnotation).filter(
        AdvisoryAnnotation.advisory_id == advisory_id
    ).order_by(desc(AdvisoryAnnotation.created_at)).all()


@router.post("/advisories/{advisory_id}/annotations", response_model=AnnotationOut, status_code=201)
async def add_annotation(
    advisory_id: int,
    data: AnnotationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
):
    adv = db.query(Advisory).filter(Advisory.id == advisory_id).first()
    if not adv:
        raise HTTPException(status_code=404, detail="Advisory not found")
    annotation = AdvisoryAnnotation(
        advisory_id=advisory_id,
        user_id=current_user.id,
        content=data.content,
    )
    db.add(annotation)
    db.commit()
    db.refresh(annotation)
    return annotation


@router.delete("/annotations/{annotation_id}", status_code=204)
async def delete_annotation(
    annotation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    ann = db.query(AdvisoryAnnotation).filter(AdvisoryAnnotation.id == annotation_id).first()
    if not ann:
        raise HTTPException(status_code=404, detail="Annotation not found")
    if ann.user_id != current_user.id and current_user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Permission denied")
    db.delete(ann)
    db.commit()


@router.get("/tasks", response_model=List[TaskOut])
async def get_tasks(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    q = db.query(AnalystTask)
    if current_user.role != UserRole.admin:
        q = q.filter(AnalystTask.assigned_to == current_user.id)
    return q.order_by(desc(AnalystTask.created_at)).all()


@router.post("/tasks", response_model=TaskOut, status_code=201)
async def create_task(
    data: TaskCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
):
    task = AnalystTask(
        advisory_id=data.advisory_id,
        assigned_to=data.assigned_to,
        assigned_by=current_user.id,
        title=data.title,
        due_date=data.due_date,
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


@router.put("/tasks/{task_id}/status", response_model=TaskOut)
async def update_task_status(
    task_id: int,
    new_status: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    task = db.query(AnalystTask).filter(AnalystTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    task.status = new_status
    db.commit()
    db.refresh(task)
    return task
