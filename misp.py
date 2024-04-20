from pymisp import PyMISP
from config import Config
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

misp_api = PyMISP(Config.MISP_URL, Config.MISP_KEY, ssl=Config.MISP_VERIFYCERT)

def search_hashes_in_misp(hashes):
    found_hashes = []
    for hash_type, hash_values in hashes.items():
        for value in hash_values:
            logging.info(f"Searching MISP for hash type '{hash_type}' with value '{value}'")
            try:
                response = misp_api.search(controller='attributes', type_attribute=hash_type, value=value)
                #logging.info(f"Search query completed. Response: {response}")
                if response and 'Attribute' in response:
                    logging.info(f"Found matching events for hash {value}: {response}")
                    found_hashes.append({'type': hash_type, 'value': value})
                else:
                    logging.info("No matching events found for hash: " + value)
            except Exception as e:
                logging.error(f"Error searching for hash {value}: {e}")
    return found_hashes

