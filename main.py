''' Fetch and return values from the API

Run the relevant commands to fetch and return database table values.
If the provided object id does not exist, fetch the values from the
VirusTotal API and insert into the database, then retrieve the values
'''
import re

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

import crud
import models
import schemas

# Make sure that the folder for the command line and the editors are the same
from api_script import domain_ip_values, files_values
from database import SessionLocal, engine

#from typing import Optional

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Dependency
def get_db():
    '''Get the database session from database.py '''
    db_session = SessionLocal()
    try:
        yield db_session
    finally:
        db_session.close()

@app.get("/")
def read_root():
    '''Placeholder value for directory'''
    return {"/scan": "test"}

@app.get("/scan")
def scan():
    '''Placeholder value for /scan'''
    return {
        "scan/domain_ip/(object_id)": "Searches domain_ip table for values",
        "scan/files/(object_id)": "Searches the files table for values"
    }


def insert_into_files(session, values):
    ''' Insert file values into the files table

    Insert the values into the respective tables and
    commit the changes.

    Args:
        session: The database session
        values: The tuple containing the values to be inserted into the
          tables files, and execution_parents respectively
    '''
    for entry in values:
        if isinstance(entry, tuple):
            session.add(
                models.Files(
                    file_id = entry[0],
                    file_name = entry[1],
                    file_date_scanned = entry[2],
                    score = entry[3],
                    severity = entry[4],
                    exec_parent_count = entry[5]
                )
            )
            session.commit()
        elif isinstance(entry, list):
            for tuples in entry:
                session.add(
                    models.Execution_Parents(
                        parent_id = tuples[0],
                        related_file_id = tuples[1],
                        exec_date_scanned = tuples[2],
                        detection_score = tuples[3],
                        severity = tuples[4],
                        parent_type = tuples[5]
                    )
                )
                session.commit()
def insert_into_domain_ip(session, values):
    ''' Insert domain/ip values into the domain_ip table

    Insert the values into the respective tables and
    commit the changes.

    Args:
        session: The database session
        values: The tuple containing the values to be inserted into the
          tables domain_ip, referrer_files, and communicating_files
          respectively
    '''
    # Files values
    session.add(
        models.Domain_Ip(
            object_id = values[0][0],
            object_type = values[0][1],
            object_last_updated = values[0][2],
            score = values[0][3],
            severity = values[0][4],
            comm_count = values[0][5],
            ref_count = values[0][6]
        )
    )
    session.commit()

    # Referrer_files values
    for dicts in values[1]:
        session.add(
            models.Referrer_Files(
                ref_file_id = dicts[0],
                ref_file_name = dicts[1],
                related_object_id = dicts[2],
                date_scanned = dicts[3],
                detection_score = dicts[4],
                severity = dicts[5],
                ref_file_type = dicts[6]
            )
        )
        session.commit()

    # Referrer_files values
    for dicts in values[2]:
        session.add(
            models.Communicating_Files(
                comm_file_id = dicts[0],
                comm_file_name = dicts[1],
                related_object_id = dicts[2],
                date_scanned = dicts[3],
                detection_score = dicts[4],
                severity = dicts[5],
                comm_file_type = dicts[6]
            )
        )
        session.commit()


@app.get("/scan/domain_ip/{object_id}", response_model = schemas.DomainIp)
def check_database_domain_ip(object_id: str, db_session: Session = Depends(get_db)):
    ''' Return value of the domain_ip, referrer_files and communicating files table

    Check the object_id input. If it is a valid domain name or ip address,
    connect to the postgresql database and run relevant commands
    and return table values. If not, return error result.

    Args:
        file_id: The sha256 hash of the file being searched for in
          the files table.

    Returns:
        Dict. Contains dict and list of values from the domain_ip
        referrer_files and communicating_files tables respectively.
        If invalid hash is provided, error message is removed.
    '''
    domain_ip_result = {"error": "invalid object id"}
    if( # Check input against regex
        re.search( # Ip address regex
            r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
            r"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
            object_id
        )
        or re.search( # Domain name regex
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]",
            object_id
        )
    ):
        domain_ip_result = crud.get_domain_ip(db_session, object_id = object_id)

        if domain_ip_result is None:
            insert_into_domain_ip(db_session, domain_ip_values(object_id))
            domain_ip_result = crud.get_domain_ip(db_session, object_id = object_id)

            if domain_ip_result is None:
                raise HTTPException(status_code=404, detail="Domain/Ip not found")

    return domain_ip_result

@app.get("/scan/files/{file_id}", response_model = schemas.Files)
def check_database_files(file_id: str, db_session: Session = Depends(get_db)):
    ''' Return value of the files and execution_parents table

    Check the file_id input. If it is a valid sha256 file hash,
    connect to the postgresql database and run relevant commands
    and return table values. If not, return error result.

    Args:
        file_id: The sha256 hash of the file being searched for in
          the files table.

    Returns:
        Dict. Contains dict and list of values from the files and
        execution_parents tables respectively. If invalid hash is
        provided, error message is removed.
    '''
    files_result = {"error": "invalid file id"}
    if len(file_id) == 64:
        files_result = crud.get_files(db_session, file_id = file_id)

        if files_result is None:
            insert_into_files(db_session, files_values(file_id))
            files_result = crud.get_files(db_session, file_id = file_id)

            if files_result is None:
                raise HTTPException(status_code=404, detail="File not found")

    return files_result
