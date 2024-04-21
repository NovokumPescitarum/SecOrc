from pymisp import PyMISP
from config import Config
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

misp_api = PyMISP(Config.MISP_URL, Config.MISP_KEY, ssl=Config.MISP_VERIFYCERT)

def search_iocs_in_misp(iocs):
    found_iocs = []
    for ioc_type, ioc_values in iocs.items():
        if ioc_type.endswith("_hash"):
            ioc_type = ioc_type[:-5]
        for value in ioc_values:
            if value:  # Check if the value is not empty
                logging.info(f"Searching MISP for {ioc_type} '{value}'")
                try:
                    response = misp_api.search(controller='attributes', value=value)
                    if response and 'Attribute' in response:
                        if response['Attribute']:  # Check if the 'Attribute' list is not empty
                            logging.info(f"Found matching events for {ioc_type} '{value}'")
                            found_iocs.append({'type': ioc_type, 'value': value})
                        else:
                            logging.info(f"No matching events found for {ioc_type} '{value}'")
                    else:
                        logging.info(f"No matching events found for {ioc_type} '{value}'")
                except Exception as e:
                    logging.error(f"Error searching for {ioc_type} '{value}': {e}")
    return found_iocs

