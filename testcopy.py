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

if __name__ == '__main__':
    #connect("0ccac46432202d7f62d79a195b9b10b116e1e1a7b1849a7cafa38f360e6dc525")
    #connect("wordcounter.net")
    #connect("google.com")
    #domain_ip_values("google.com")
    print(len(files_values("ca27950b280b290f61c7bd113cf873384e662c047a20b8fbce1f73cda2a70c92")[1]))
