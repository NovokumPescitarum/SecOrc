import logging

def extract_data(json_data):
    """ Recursively extract data from JSON into a flat dictionary. """
    extracted_data = {}

    def recursive_extract(data, parent_key=''):
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    recursive_extract(value, parent_key + key + '_')
                else:
                    extracted_data[parent_key + key] = value
        elif isinstance(data, list):
            for i, item in enumerate(data):
                recursive_extract(item, parent_key + str(i) + '_')
        else:
            extracted_data[parent_key[:-1]] = data  

    recursive_extract(json_data)
    
    # Extract specific data points
    source_ip = extracted_data.get('all_fields_agent_ip', 'N/A')
    destination_ip = extracted_data.get('all_fields_data_win_eventdata_destinationIp', 'N/A')
    url = extracted_data.get('url', 'N/A')
    file_path = extracted_data.get('all_fields_data_win_eventdata_image', 'N/A')
    hash_data_string = extracted_data.get('all_fields_data_win_eventdata_hashes', '')

    # Extract hashes using parse_hash_data function
    hashes = parse_hash_data(hash_data_string)


    return extracted_data

def parse_hash_data(hash_string):
    """ Parse hash data from a given string and organize them into a dictionary with lists of values for each hash type.
    Supports multiple hash values of the same type.
    """
    # Initialize a dictionary to store lists of hash values, keyed by hash type
    hashes = {'md5': [], 'sha256': [], 'imphash': [], 'sha1':[]}
    
    if hash_string:
        # Split the string by commas to separate each hash entry
        hash_parts = hash_string.split(',')
        for part in hash_parts:
            # Check if each part contains an '=' indicating a valid key-value pair
            if '=' in part:
                try:
                    hash_type, hash_value = part.split('=', 1)  # Split only on the first '=' to ensure correct parsing
                    hash_type = hash_type.lower().strip()
                    hash_value = hash_value.strip()
                    # Append the hash value to the correct list based on hash type if it is a recognized type
                    if hash_type in hashes:
                        hashes[hash_type].append(hash_value)
                    else:
                        logging.warning(f"Unrecognized hash type '{hash_type}' encountered.")
                except ValueError as e:
                    logging.error(f"Error parsing hash data '{part}': {e}")
            else:
                logging.warning(f"Invalid hash entry '{part}' encountered in hash string.")
    
    # Clean up the dictionary to remove any empty lists
    hashes = {k: v for k, v in hashes.items() if v}
    
    return hashes
