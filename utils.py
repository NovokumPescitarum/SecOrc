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
    return extracted_data

def parse_hash_data(hash_string):
    """ Parse hash data from a given string and organize them in a dictionary with lists of values for each hash type. """
    hashes = {'md5': [], 'sha256': [], 'imphash': []}
    logging.info(f"Parsing hash data string: {hash_string}")
    if hash_string:
        hash_parts = hash_string.split(',')
        for part in hash_parts:
            if '=' in part:
                hash_type, hash_value = part.split('=')
                hash_type = hash_type.lower().strip()
                # Append the hash value to the correct list based on hash type
                if hash_type == 'md5':
                    hashes['md5'].append(hash_value.strip())
                elif hash_type == 'sha256':
                    hashes['sha256'].append(hash_value.strip())
                elif hash_type == 'imphash':
                    hashes['imphash'].append(hash_value.strip())
    # Remove any empty lists
    hashes = {k: v for k, v in hashes.items() if v}
    logging.info(f"Extracted hashes: {hashes}")
    return hashes
