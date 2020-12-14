'''SQLAlchemy models'''
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from database import Base

class Files(Base):
    '''files model'''
    __tablename__ = "files"

    file_id = Column(String, primary_key = True)
    file_name = Column(String)
    file_date_scanned = Column(String)
    score = Column(String)
    severity = Column(String)
    exec_parent_count = Column(Integer)

    exec_parent = relationship("Execution_Parents")

class Execution_Parents(Base):
    '''execution_parents model'''
    __tablename__ = "execution_parents"

    parent_id = Column(String, primary_key = True)
    related_file_id = Column(String, ForeignKey("files.file_id"))
    exec_date_scanned = Column(String)
    detection_score = Column(String)
    severity = Column(String)
    parent_type = Column(String)

class Domain_Ip(Base):
    '''domain_ip model'''
    __tablename__ = "domain_ip"

    object_id = Column(String, primary_key = True)
    object_type = Column(String)
    object_last_updated = Column(String)
    score = Column(String)
    severity = Column(String)
    comm_count = Column(Integer)
    ref_count = Column(Integer)

    ref_files = relationship("Referrer_Files")
    comm_files = relationship("Communicating_Files")

class Referrer_Files(Base):
    '''referrer_files model'''
    __tablename__ = "referrer_files"

    ref_file_id = Column(String, primary_key = True)
    ref_file_name = Column(String)
    related_object_id = Column(String, ForeignKey("domain_ip.object_id"))
    date_scanned = Column(String)
    detection_score = Column(String)
    severity = Column(String)
    ref_file_type = Column(String)

class Communicating_Files(Base):
    '''communicating_files model'''
    __tablename__ = "communicating_files"

    comm_file_id = Column(String, primary_key = True)
    comm_file_name = Column(String)
    related_object_id = Column(String, ForeignKey("domain_ip.object_id"))
    date_scanned = Column(String)
    detection_score = Column(String)
    severity = Column(String)
    comm_file_type = Column(String)
