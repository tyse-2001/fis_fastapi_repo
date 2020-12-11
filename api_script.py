''' Connect to the postgresql db and insert values for domain, ip and file api objects.

Connects to the db, and the connect function checks if the input is a
domain, ip, or file. If true, fetch the relevant values from the
VirusTotal API and and insert them into the db.
'''
import asyncio
import json
import re
from datetime import MINYEAR, datetime

import psycopg2
import requests
from psycopg2 import sql

X_APIKEY = '9f32818f9c098d578adb826c57518a27fd484dc1c41c7cdcb879bd414b141b4a'

def severity_calc(score):
    ''' Calculates the percentage of the score field and assigns it a rating accordingly.

    Args:
        score: The value for the detection score fields of the table.

    Returns:
        String. A rating of 'low', 'medium', 'high', or 'none' based on the value
        of score.
    '''
    rating = "none"
    values = score.split('/')

    if values[1] != "0":
        percentage = int(values[0])/int(values[1])
        if percentage <= 0.2:
            rating = "low"
        elif 0.2 < percentage <= 0.5:
            rating = "medium"
        else:
            rating = "high"

    return rating

########## DOMAINS/IP TABLES ##########
async def fetch_related_file_values(object_id, work_queue):
    list_values = []
    file_name = ""
    date_scanned = ""
    while not work_queue.empty():
        dicts = await work_queue.get()
        attributes = dicts["attributes"]
        if "meaningful_name" in attributes:
            file_name = attributes["meaningful_name"]
        if "last_analysis_date" in attributes:
            date_scanned = datetime.utcfromtimestamp(
                attributes["last_analysis_date"]
            ).strftime("%Y-%m-%d %H:%M:%S") + " UTC"
        else:
            date_scanned = datetime.utcfromtimestamp(
                MINYEAR
            ).strftime('%Y-%m-%d %H:%M:%S') + " UTC"
            print(
                "Last scan date not found for referrer file entry. "
                "Will be set to earliest value."
            )
        file_detections = (
            attributes["last_analysis_stats"]["malicious"]
            + attributes["last_analysis_stats"]["suspicious"]
        )
        total = sum(attributes["last_analysis_stats"].values())
        detection_score = str(file_detections) + "/" + str(total)

        related_file_entries = (
            attributes["sha256"], # ref_file_id/comm_file_id
            file_name, #ref_file_name/comm_file_name
            object_id, # related_object_id
            date_scanned,
            detection_score,
            severity_calc(detection_score), # severity
            attributes["type_description"] # ref_file_type/comm_file_type
        )
        list_values.append(related_file_entries)
    return list_values

### REFERRER_FILES FIELDS ###
async def ref_values(ref_dict, object_id, referrer_entries_list = None):
    ''' Fetches and returns the values for the referrer_files table.

    The list contiaining the dicts is looped through, and the relevant
    values are returned and appended to referrer_entries_list.

    If there are additional entries past the initial 40, the function is
    run recursively with the new link and subsequent lists are returned
    and appeneded.

    Args:
        ref_dict: The dict containing the json response for the related
          domain/ip object.
        object_id: The domain/ip being searched for in the VirusTotal API.
        referrer_entries_list: The list containing the tuples with the
          values for the domain_ip table. Default value is an empty list.

    Returns:
        A list of tuples that contain the retrieved values for the
        referrer_files table.

    Raises:
        KeyError: An error occured accessing the dict values.
    '''
    if referrer_entries_list is None:
        referrer_entries_list = []
    
    ref_work_queue = asyncio.Queue()

    if not "error" in ref_dict:
        for dicts in ref_dict["data"]: # Looping through dicts in list
            if not "error" in dicts:
                await ref_work_queue.put(dicts)
        
        referrer_entries = await asyncio.gather(
            asyncio.create_task(fetch_related_file_values(object_id, ref_work_queue)),
            asyncio.create_task(fetch_related_file_values(object_id, ref_work_queue)),
            asyncio.create_task(fetch_related_file_values(object_id, ref_work_queue)),
            asyncio.create_task(fetch_related_file_values(object_id, ref_work_queue)),
        )

        referrer_entries_list.extend(referrer_entries[0])

        if "next" in ref_dict["links"]:
            next_ref_dict = json.loads(
                requests.get(
                    ref_dict["links"]["next"],
                    headers = {
                        "x-apikey": X_APIKEY
                    }
                ).text
            )
            next_ref_list = await ref_values(
                next_ref_dict,
                object_id,
                referrer_entries_list
            )

    return referrer_entries_list

### COMMUNICATING_FILES FIELDS ###
async def comm_values(comm_dict, object_id, communicating_entries_list = None):
    ''' Fetches and returns the values for the communicating_files table.

    The list contiaining the dicts will be looped through, and the relevant
    values will be returned and appended to referrer_entries_list.

    If there are additional entries past the initial 40, the function will
    be run recursively with the new link and the subsequent lists will be
    returned and appeneded.

    Args:
        comm_dict: The dict containing the json response for the related
          domain/ip object.
        object_id: The domain/ip being searched for in the VirusTotal API.
        referrer_entries_list: The list containing the tuples with the
          values for the domain_ip table. Default value is an empty list.

    Returns:
        A list of tuples that contain the retrieved values for the
        communicating_files table.

    Raises:
        KeyError: An error occured accessing the dict values.
    '''
    if communicating_entries_list is None:
        communicating_entries_list = []

    comm_work_queue = asyncio.Queue()

    if not "error" in comm_dict:
        for dicts in comm_dict["data"]: # Looping through dicts in list
            if not "error" in dicts:
                await comm_work_queue.put(dicts)

        communicating_entries = await asyncio.gather(
            asyncio.create_task(fetch_related_file_values(object_id, comm_work_queue)),
            asyncio.create_task(fetch_related_file_values(object_id, comm_work_queue)),
            asyncio.create_task(fetch_related_file_values(object_id, comm_work_queue)),
            asyncio.create_task(fetch_related_file_values(object_id, comm_work_queue)),
        )

        communicating_entries_list.extend(communicating_entries[0])

        if "next" in comm_dict["links"]:
            next_ref_dict = json.loads(
                requests.get(
                    comm_dict["links"]["next"],
                    headers = {
                        "x-apikey": X_APIKEY
                    }
                ).text
            )
            next_ref_list = await comm_values(next_ref_dict, object_id, communicating_entries_list)

    return communicating_entries_list

### DOMAIN_IP FIELDS ###
def domain_ip_entries(url, object_dict):
    ''' Returns the values for tables: domain_ip, referrer_files, and communicating_files.

    Retrieves the relevant values for the files table from the dict first,
    followed by the entries for referring_files and communicating_files
    table by running ref_values() and comm_values() respectively.

    Args:
        url: The url for the domain/ip, used for getting the json response
          from the VirusTotal API.
        object_dict: The dict containing the values from the API.

    Returns:
        A tuple containing the retrived values for domain_ip,
        referring_files, and communicating_files.

    Raises:
        KeyError: An error occured accessing the dict values.
    '''
    object_entry = ()
    ref_list = []
    comm_list = []

    if not "error" in object_dict:
        try:
            object_last_updated = ""

            if "whois_date" in object_dict["data"]["attributes"]:
                object_last_updated = datetime.utcfromtimestamp( # object_last_updated
                    object_dict["data"]["attributes"]["whois_date"]
                ).strftime("%Y-%m-%d %H:%M:%S") + " UTC"
            else:
                object_last_updated = datetime.utcfromtimestamp(
                    MINYEAR
                ).strftime('%Y-%m-%d %H:%M:%S') + " UTC"
                print(
                    "Last scan date not found for domain/ip entry. "
                    "Will be set to earliest value."
                )
            detections = (
                object_dict["data"]["attributes"]["last_analysis_stats"]["suspicious"]
                + object_dict["data"]["attributes"]["last_analysis_stats"]["malicious"]
            )
            total = sum(object_dict["data"]["attributes"]["last_analysis_stats"].values())
            score = str(detections) + "/" + str(total)

            comm_file_url = url + "/communicating_files?limit=40"
            comm_file_dict = json.loads(
                requests.get(
                    comm_file_url,
                    headers = {
                        "x-apikey": X_APIKEY
                    }
                ).text
            )

            ref_file_url = url + "/referrer_files?limit=40"
            ref_file_dict = json.loads(
                requests.get(
                    ref_file_url,
                    headers = {
                        "x-apikey": X_APIKEY
                    }
                ).text
            )

            object_entry = (
                object_dict["data"]["id"], # object_id
                object_dict["data"]["type"], # object_type
                object_last_updated,
                score,
                severity_calc(score), # severity
                comm_file_dict["meta"]["count"], # comm_count
                ref_file_dict["meta"]["count"] # ref_count
            )

            ref_list = asyncio.run(ref_values(ref_file_dict, object_dict["data"]["id"]))
            comm_list = asyncio.run(comm_values(comm_file_dict, object_dict["data"]["id"]))
        except KeyError as k:
            print(
                "An exception of type {0} occurred. Arguments:\n{1!r}".format(
                    type(k).__name__,
                    k.args
                )
            )
            print(
                "An error has occured accessing the domain/ip values.\n"
                "There may be missing values from the returned list"
            )

    return(object_entry, ref_list, comm_list)
def domain_ip_values(domain_ip):
    ''' Fetches and returns the entries for the domain_ip table.

    Checks if the given domain_ip values is a domain name or an ip
    address using a regular expression, then prepares the appropriate url
    and dict to be passed to domain_ip_entries().

    If domain_ip does not match either of the two regex, a tuple
    containing two empty tuples is returned instead.

    Args:
        domain_ip: The domain/ip being searched for in the VirusTotal API.

    Returns:
        Tuples that contain the retrieved values of the communicating_files
        table. If the given input does not match either of the regular
        expressions, a tuple containing three empty tuples is returned
        instead.
    '''
    entries = ((), [], [])
    api_url = ""

    if re.search( # ip address regex
        r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
        r"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
        domain_ip
    ):
        api_url = "https://virustotal.com/api/v3/ip_addresses/" + str(domain_ip)
    elif re.search( # domain name regex
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]",
        domain_ip
    ):
        api_url = "https://virustotal.com/api/v3/domains/" + str(domain_ip)
    else:
        print("This is not an IP or Domain")
        return entries

    # Convert the json response to dict
    api_dict = json.loads(requests.get(api_url, headers = {"x-apikey": X_APIKEY}).text)
    entries = domain_ip_entries(api_url, api_dict)

    return entries
########## DOMAINS/IP TABLES ##########


########## FILES TABLES ##########
async def fetch_exec_parent_values(file_id, work_queue):
    list_values = []
    exec_date_scanned = ""
    while not work_queue.empty():
        dicts = await work_queue.get()
        attributes = dicts["attributes"]
        if "last_analysis_date" in attributes:
            exec_date_scanned = datetime.utcfromtimestamp(
                attributes["last_analysis_date"]
            ).strftime("%Y-%m-%d %H:%M:%S") + " UTC"
        else:
            exec_date_scanned = datetime.utcfromtimestamp(
                MINYEAR
            ).strftime('%Y-%m-%d %H:%M:%S') + " UTC"
            print(
                "Last scan date not found for execution parent. "
                "Will be set to earliest value."
            )

        exec_detections = (
            attributes["last_analysis_stats"]["malicious"]
            + attributes["last_analysis_stats"]["suspicious"]
        )
        exec_total = sum(attributes["last_analysis_stats"].values())
        detection_score = str(exec_detections) + "/" + str(exec_total)

        exec_entries = (
            dicts["attributes"]["sha256"], # parent_id
            file_id, # related_file_id
            exec_date_scanned,
            detection_score,
            severity_calc(detection_score), # severity
            dicts["attributes"]["type_description"] # parent_type
        )
        list_values.append(exec_entries)
    return list_values

### EXECUTION_PARENTS FIELDS ###
async def exec_values(exec_parent_dict, file_id, exec_entries_list = None):
    ''' Returns the values for the execution_parents table.

    The list contiaining the dicts will be looped through, and the relevant
    values will be returned and appended to referrer_entries_list.

    If there are additional entries past the initial 40, the function will
    be run recursively with the new link and the subsequent lists will be
    returned and appeneded.

    Args:
        exec_parent_dict: The dict containing the json response for the
          related file.
        file_id: The hash of the file being searched for in the VirusTotal
          API.
        exec_entries_list: The list containing the tuples with the
          values for the excution_parents table. Default value is an empty
          list.

    Returns:
        A list of tuples that contain the retrieved values for the
        execution_parents table.

    Raises:
        KeyError: An error occured accessing the dict values.
    '''
    if exec_entries_list is None:
        exec_entries_list = []

    exec_work_queue = asyncio.Queue()

    if not "error" in exec_parent_dict:
        for dicts in exec_parent_dict["data"]: #Looping through list with dicts inside
            if not "error" in dicts:
                await exec_work_queue.put(dicts)

            exec_entries = await asyncio.gather(
                asyncio.create_task(fetch_exec_parent_values(file_id, exec_work_queue)),
                asyncio.create_task(fetch_exec_parent_values(file_id, exec_work_queue)),
                asyncio.create_task(fetch_exec_parent_values(file_id, exec_work_queue)),
                asyncio.create_task(fetch_exec_parent_values(file_id, exec_work_queue)),
            )

            exec_entries_list.extend(exec_entries[0])

        if "next" in exec_parent_dict["links"]:
            next_ref_dict = json.loads(
                requests.get(
                    exec_parent_dict["links"]["next"],
                    headers = {
                        "x-apikey": X_APIKEY
                    }
                ).text
            )
            next_ref_list = await exec_values(next_ref_dict, file_id, exec_entries_list)

    return exec_entries_list

### FILES FIELDS ###
def files_values(file_hash):
    ''' Returns the values for the files table.

    It checks the provided sha256 hash for its length and type. If it is 64
    characters long and is a string, the values for the file are retrieved
    from the VirusTotal API. Otherwise, it informs the user that the hash
    is invalid and does not run.

    Args:
        file_hash: The sha256 hash of the file being searched for in the VirusTotal
          API.

    Returns:
        The entries for the files and execution_parents table respectively.
        If the hash is invalid, two empty tuples are returned instead.
    '''
    file_entry = ()
    exec_list = []

    file_name = ""

    if(len(file_hash) == 64 and isinstance(file_hash, str)):
        file_url = "https://virustotal.com/api/v3/files/" + file_hash
        file_dict = json.loads(requests.get(file_url, headers = {"x-apikey": X_APIKEY}).text)

        if not "error" in file_dict:
            try:
                file_date_scanned = ""

                if "meaningful_name" in file_dict["data"]["attributes"]:
                    file_name = file_dict["data"]["attributes"]["meaningful_name"]
                if "last_analysis_date" in file_dict["data"]["attributes"]:
                    file_date_scanned = datetime.utcfromtimestamp(
                        file_dict["data"]["attributes"]["last_analysis_date"]
                    ).strftime('%Y-%m-%d %H:%M:%S') + " UTC"
                else:
                    file_date_scanned = datetime.utcfromtimestamp(
                        MINYEAR
                    ).strftime('%Y-%m-%d %H:%M:%S') + " UTC"
                    print("Last scan date not found for file entry. Will be set to earliest value.")

                file_detections = (
                    file_dict["data"]["attributes"]["last_analysis_stats"]["suspicious"]
                    + file_dict["data"]["attributes"]["last_analysis_stats"]["malicious"]
                )
                file_total = sum(file_dict["data"]["attributes"]["last_analysis_stats"].values())
                file_detection_score = str(file_detections) + "/" + str(file_total)

                exec_file_url = file_url + "/execution_parents?limit=40"
                exec_file_dict = json.loads(
                    requests.get(
                        exec_file_url,
                        headers = {
                            "x-apikey": X_APIKEY
                        }
                    ).text
                )

                file_entry = (
                    file_dict["data"]["attributes"]["sha256"], # file_id
                    file_name, # file_name
                    file_date_scanned,
                    file_detection_score,
                    severity_calc(file_detection_score), # severity
                    exec_file_dict["meta"]["count"] # exec_parent_count
                )
                exec_list = asyncio.run(exec_values(exec_file_dict, file_dict["data"]["attributes"]["sha256"]))
            except KeyError as k:
                print(
                    "An exception of type {0} occurred. Arguments:\n{1!r}".format(
                        type(k).__name__,
                        k.args
                    )
                )
    else:
        print(
            "The provided sha256 hash was not 64 characters long, or it was not a string.\n"
            "Please provide a valid sha256 hash."
        )
        print(len(file_hash), type(file_hash))

    return(file_entry, exec_list)
########## FILES TABLES ##########


########## DATABASE CONNECTION ##########
def pk_check(table_entry, cursor, table_name = "domain_ip"):
    ''' Checks the database to see if there are any duplicate primary keys.

    It retrieves the column name of the primary key, then fetches all the
    values from that column. It loops through the values and checks it
    against the value in table_entry.

    Args:
        table_entry: Tuple containing the entries to be inserted into
          the database table.
        cursor: Cursor used when connecting to database
        table_name: The name of the table to be checked

    Returns:
        Boolean value. If the values in table_entry matches the existing
        table value, it returns True. Otherwise, returns False.
    '''

    # Command to retrive primary key of table
    cursor.execute('''SELECT a.attname
        FROM   pg_index i
        JOIN   pg_attribute a ON a.attrelid = i.indrelid
        AND a.attnum = ANY(i.indkey)
        WHERE  i.indrelid = %s::regclass
        AND    i.indisprimary;''', (table_name,))
    p_key = cursor.fetchall()[0][0]

    request = sql.SQL(
        '''
        SELECT
            {p_key}
        FROM
            {table_name}
        '''
    ).format(
        p_key = sql.Identifier(p_key),
        table_name = sql.Identifier(table_name)
    )

    cursor.execute(request)
    pk_values = cursor.fetchall() # Here we have all of the primary key values for that table

    check = 0
    for value in pk_values:
        if table_entry[0] == value[0]:
            check = 1
            break

    return check

def file_connect(connection, cursor, files):
    ''' Executes the sql commands for the file object type.

    Checks if the files parameter is empty. If not, the value of the
    entry is checked against the values of the primary key using pk_check(),
    and the sql command is run to insert the values if pk_check() returns
    False.

    Args:
        connection: The database connection
        cursor: Cursor used when connecting to database
        files: The values of the files to be inserted into the datebase

    Returns:
        The entries that pass the checks will be inserted into the table.
        No values are returned.
    '''
    if files[0]:
        for entry in files:
            if isinstance(entry, tuple):
                if pk_check(entry, cursor, "files"):
                    print(
                        "There is already an entry in the files "
                        "table with the current object id.\n"
                        "No commands will be run."
                    )
                    break

                cursor.execute(
                    "prepare files_request(text, text, text, text, text, int) as "
                    "INSERT INTO files VALUES($1, $2, $3, $4, $5, $6)"
                    )

                cursor.execute("execute files_request (%s, %s, %s, %s, %s, %s)", files[0])
                connection.commit()
                #print("Inserted files table values")
            elif isinstance(entry, list):
                cursor.execute(
                        "prepare execution_parents_request(text, text, text, text, text, text) as "
                        "INSERT INTO execution_parents VALUES($1, $2, $3, $4, $5, $6)"
                        )
                for tuples in entry:
                    cursor.execute(
                        "execute execution_parents_request (%s, %s, %s, %s, %s, %s)",
                        tuples
                    )
                    connection.commit()
                    #print("Inserted execution_parents table values")
    else:
        print("No requests will be carried out as there are no file values to insert")
def domain_ip_connect(connection, cursor, domain_ip):
    ''' Executes the sql commands for the domain/ip object type.

    Checks if the domain parameter is empty. If not, the value of the
    entry is checked against the values of the primary key using pk_check(),
    and the sql command is run to insert the values if pk_check() returns
    False.

    Args:
        connection: The database connection
        cursor: Cursor used when connecting to database
        domain_ip: The domain/ip being searched for in the VirusTotal API.

    Returns:
        The entries that pass the checks will be inserted into the table.
        No values are returned.
    '''
    if domain_ip[0]:
        if pk_check(domain_ip[0], cursor, "domain_ip"):
            print(
                "There is already an entry in the files table with the current object id.\n"
                "No commands will be run."
            )
        else:
            cursor.execute(
                "prepare domain_ip_request(text, text, text, text, text, int, int) as "
                "INSERT INTO domain_ip VALUES($1, $2, $3, $4, $5, $6, $7)"
                )
            cursor.execute("execute domain_ip_request (%s, %s, %s, %s, %s, %s, %s)", domain_ip[0])
            connection.commit()
            #print("Inserted domain_ip table values")

            cursor.execute( # Prepared statement for referrer_files
                "prepare referrer_files_request(text, text, text, text, text, text, text) as "
                "INSERT INTO referrer_files VALUES($1, $2, $3, $4, $5, $6, $7)"
                )
            for values in domain_ip[1]: # List of tuples
                if isinstance(values, tuple):
                    cursor.execute(
                        "execute referrer_files_request (%s, %s, %s, %s, %s, %s, %s)",
                        values
                    )
                    connection.commit()
                    #print("Inserted referrer_files table values")

            cursor.execute( # Prepared statement for communicating_files
                "prepare communicating_files_request(text, text, text, text, text, text, text) as "
                "INSERT INTO communicating_files VALUES($1, $2, $3, $4, $5, $6, $7)"
                )
            for values in domain_ip[2]: # List of tuples
                if isinstance(values, tuple):
                    cursor.execute(
                        "execute communicating_files_request (%s, %s, %s, %s, %s, %s, %s)",
                        values
                    )
                    connection.commit()
                    #print("Inserted communicating_files table values")
    else:
        print("No requests will be carried out")
def connect(api_object):
    ''' Connect to the PostgreSQL database server

    Checks if the input is a string, and connects to the database if it is.
    The input is then checked to see if it is a domain name, ip address, or
    sha 256 hash, then runs domain_ip_connect() or file_connect() accordingly.

    Args:
        api_object: Domain name, ip address, or sha 256 hash

    Returns:
        No values are returned.
    '''
    if isinstance(api_object, str):
        conn = None
        try:
            # connect to the PostgreSQL server
            print("Connecting to the PostgreSQL database...")
            conn = psycopg2.connect(
                host="localhost",
                database="postgres",
                user="postgres",
                password="03052001"
                )

            # create a cursor
            cur = conn.cursor()

            # execute requests
            if(
                re.search( # Ip address regex
                    r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
                    r"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
                    api_object
                )
                or re.search( # Domain name regex
                    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]",
                    api_object
                )
            ):
                domain_ip_connect(conn, cur, domain_ip_values(api_object))
            elif len(api_object) == 64:
                file_connect(conn, cur, files_values(api_object))
            else:
                print(
                    "The given input is not a domain name, ip address, nor a sha256 hash.\n"
                    "No commands will be run."
                )

            # close the communication with the PostgreSQL
            cur.close()
        except psycopg2.DatabaseError as error:
            print(error)
        finally:
            if conn is not None:
                conn.close()
                print("Database connection closed.")
    else:
        print("The provided input is not a string. Please proivde valid input")
########## DATABASE CONNECTION ##########


if __name__ == '__main__':
    #connect("ca27950b280b290f61c7bd113cf873384e662c047a20b8fbce1f73cda2a70c92")
    #connect("google.com")
    pass
