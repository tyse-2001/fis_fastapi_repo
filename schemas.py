from typing import List

from pydantic import BaseModel


class ExecutionParentsBase(BaseModel):
    parent_id: str
    related_file_id: str
    exec_date_scanned: str
    detection_score: str
    severity: str
    parent_type: str

class ExecutionParentsCreate(ExecutionParentsBase):
    pass

class ExecutionParents(ExecutionParentsBase):
    class Config:
        orm_mode = True


class FilesBase(BaseModel):
    file_id: str
    file_name: str
    file_date_scanned: str
    score: str
    severity: str
    exec_parent_count: int

class FilesCreate(FilesBase):
    pass

class Files(FilesBase):
    exec_parent: List[ExecutionParents] = []

    class Config:
        orm_mode = True


class ReferrerFilesBase(BaseModel):
    ref_file_id: str
    ref_file_name: str
    related_object_id: str
    date_scanned: str
    detection_score: str
    severity: str
    ref_file_type: str

class ReferrerFilesCreate(ReferrerFilesBase):
    pass

class ReferrerFiles(ReferrerFilesBase):
    class Config:
        orm_mode = True


class CommunicatingFilesBase(BaseModel):
    comm_file_id: str
    comm_file_name: str
    related_object_id: str
    date_scanned: str
    detection_score: str
    severity: str
    comm_file_type: str

class CommunicatingFilesCreate(CommunicatingFilesBase):
    pass

class CommunicatingFiles(CommunicatingFilesBase):
    class Config:
        orm_mode = True


class DomainIpBase(BaseModel):
    object_id: str
    object_type: str
    object_last_updated: str
    score: str
    severity: str
    comm_count: int
    ref_count: int

class DomainIpCreate(DomainIpBase):
    pass

class DomainIp(DomainIpBase):
    ref_files: List[ReferrerFiles] = []
    comm_files: List[CommunicatingFiles] = []

    class Config:
        orm_mode = True
