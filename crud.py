''' Database CRUD request functions '''
from sqlalchemy.orm import Session

import models
import schemas

def get_files(db: Session, file_id: str):
    return db.query(models.Files).filter(
        models.Files.file_id == file_id
    ).first()

def get_execution_parents(db: Session, related_file_id: str):
    return db.query(models.Execution_Parents).filter(
        models.Execution_Parents.related_file_id == related_file_id
    ).all()

def get_domain_ip(db: Session, object_id: str):
    return db.query(models.Domain_Ip).filter(
        models.Domain_Ip.object_id == object_id
    ).first()

def get_referrer_files(db: Session, related_file_id: str):
    return db.query(models.Referrer_Files).filter(
        models.Referrer_Files.related_object_id == related_file_id
    ).all()

def get_communicating_files(db: Session, related_file_id: str):
    return db.query(models.Communicating_Files).filter(
        models.Communicating_Files.related_object_id == related_file_id
    ).all()