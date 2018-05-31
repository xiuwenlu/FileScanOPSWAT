import requests
import hashlib
import json

""""" ======================== HELPER FUNCTIONS ========================== """""

def hash_file(filename):
    """
        Calculate the hash of the given file
        Input:
            filename: Name of the given file and its relative path to this file
        Output:
            returns a sha256 hash digest

    """
    print("=== Hashing File! ===")

    h = hashlib.sha256()
    try:
        with open(filename, 'rb') as fp:
            while True:
                content_chunk = fp.read(64*1024)
                if not content_chunk:
                    break
                else:
                    h.update(content_chunk)
        fp.close()
        print(h.hexdigest().upper())
        return h.hexdigest().upper()
    except:
        print("File not found!")
        return None

def hash_lookup(hashv, apikey):
    """
    Performs a hash lookup against metadefender.opswat.com. 
    Sees if there are previously cached results for this file.
        Inputs:
            1. hashv: hash of the file
            2. apikey: YOUR_API_KEY
        Output:
            1. returns True with the scanned results if Hash is cached and found
            2. returns False and Error message for any other status codes other than 200
    """

    print("=== Looking up Hash For This File! ===")

    url = 'https://api.metadefender.com/v2/hash/'+ hashv
    headers = {
        'apikey': apikey
    }
    try:
        response = requests.get(url, headers=headers)
        status = response.status_code
        if (response.ok):
            data = json.loads(response.text)
            if (hashv in data and data[hashv] == "Not Found"):
                return (False, "Not Found")
            data = json.loads(response.text)
            return (True, data)
        elif (status == 401):
            return (False, "Authentication Failed/Invalid API Key")
        else:
            return (False, "Error")
    except:
        return (False, "Lookup failed")

def OPSWAT_upload(filename, apikey):
    """
        No cached hash found. This function will upload the file onto metadefender.opswat.com
        Inputs:
            filename: Name of the given file and its relative path to this file
            apikey: YOUR_API_KEY
        Output:
            None, prints upload failed message. 
            Calls retrieve_results to retrieve the scanned results with the resulting from the upload data_id.

    """
    print("=== Hash Not Found, Uploading File! ===")

    url = "https://api.metadefender.com/v2/file"
    headers = {
      'apikey': apikey,
      'filename': filename
    }
    formData = {'file': open(filename, 'rb')}
    try:
        response = requests.post(url, files=formData, headers=headers)
        if (response.ok):
            data = json.loads(response.text)
            retrieve_results(data["data_id"], apikey)
        else:
            print ("Upload Failed due to an error, please try again!")
    except:
        print ("Upload Failed, please try again!")

def retrieve_results(data_id, apikey):
    """
        This function will retrieve_results to retrieve the scanned results with the resulting from the upload data_id.
        Inputs:
            filename: Name of the given file and its relative path to this file
            apikey: YOUR_API_KEY
        Output:
            None, prints results or failed message.  

    """
    print("=== Retrieving File Scan Results! ===")

    url = 'https://api.metadefender.com/v2/file/'+ data_id
    headers = {
        'apikey': apikey
    }
    try:
        done = 0
        while True:
            response = requests.get(url, headers=headers)
            if (response.ok):
                data = json.loads(response.text)
                if (data["scan_results"]["progress_percentage"] != 100):
                    continue
                else:
                    done = 1
                    break
        if done:
            print_data(data)
        else:
            print ("Error: Retrieval failed, please try again.")
    except:
        print ("Error: Retrieval failed, please try again.")


def print_data(data):
    """
        This function prints the scanned results formatted.
        Inputs:
            data: results that needs to be printed
        Output:
            None, prints results.  

    """
    print("=== Printing File Scan Results! ===")

    if not "file_info" in data:
        print ("Error,", data)

    filename = data["file_info"]["display_name"]
    overall_status = data["scan_results"]["scan_all_result_a"]
    scan_details = data["scan_results"]["scan_details"]
    print("filename:",filename)
    print("overall_status:", overall_status, "\n")
    for key in scan_details:
        print("engine:", key)
        threat_found = scan_details[key]["threat_found"]
        print("threat_found:", threat_found)
        print("scan_result:", scan_details[key]["scan_result_i"])
        print("def_time:", scan_details[key]["def_time"], "\n")

"""" ======================== END OF HELPER FUNCTIONS ======================== """""    



def upload_file(filename, apikey):
    """
        This function:
            1. Calculate the hash of the given samplefile.txt
            2. Perform a hash lookup against metadefender.opswat.com and see if their are previously cached results for the file
            3. If results found then skip to 6
            4. If results not found then upload the file, receive a data_id
            5. Repeatedly pull on the data_id to retrieve results
            6. Display results in format below
        Inputs:
            filename: the name of the file you want to upload
            apikey: YOUR_API_KEY
        Output:
            prints results or error message  

    """
    file_hash = hash_file(filename)
    if (file_hash):
        lookup_status, data = hash_lookup(file_hash, apikey)
        if (lookup_status):
            print_data(data)
        elif (not lookup_status and data == "Not Found"):
            OPSWAT_upload(filename, apikey)
        else:
            print(data)

"""Call this function: upload_file(filename, apikey)"""
# upload_file(filename, apikey)




