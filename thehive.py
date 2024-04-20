from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact,Case
from config import Config
from misp import search_hashes_in_misp
from utils import parse_hash_data
import logging

thehive_api = TheHiveApi(Config.THEHIVE_URL, Config.THEHIVE_KEY)

def build_alert(alert_data, alert_id):
    """ Build the alert object with detailed descriptions based on alert data. """
    severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    severity = severity_map.get(alert_data.get('severity', 'medium'), 2)
    description_items = [
        f"Hostname: {alert_data.get('all_fields_data_win_system_computer', 'N/A')}",
        f"Source IP: {alert_data.get('all_fields_agent_ip', 'N/A')}",
        f"Destination IP: {alert_data.get('all_fields_data_win_eventdata_image', 'N/A')}",
        f"Agent Name: {alert_data.get('all_fields_agent_name', 'N/A')}",
        f"Additional Info: {alert_data.get('all_fields_data_win_system_message', 'Alert generated from Wazuh event.')}"
    ]
    description = '\n'.join(description_items)
    artifacts = generate_artifacts(alert_data)
    return Alert(
        title=alert_data.get('title', 'Wazuh Alert'),
        description=description,
        severity=severity,
        tlp=severity,  # Adjust based on actual TLP levels required
        tags=['wazuh', 'auto-generated'],
        type='external',
        source='Wazuh',
        sourceRef=str(alert_id),
        artifacts=artifacts
    )

def generate_artifacts(alert_data):
    title_tag = alert_data.get('title', 'Wazuh Alert')
    exclude_keys = {'severity', 'title', 'description', 'all_fields_data_win_eventdata_hashes'}
    artifacts = []
    logging.info(f"Generating artifacts for alert: {title_tag}")
    for key, value in alert_data.items():
        if key not in exclude_keys and value:
            artifacts.append(AlertArtifact(dataType='other', data=str(value), tags=[key]))
    # Consider adding handling for hash data if needed
    return artifacts

def submit_alert(alert):
    """ Submit an alert to TheHive and log the response. """
    try:
        response = thehive_api.create_alert(alert)
        if response.status_code == 201:
            logging.info(f"Alert successfully created in TheHive with ID: {response.json()['id']}")
            return True, response.json()
        else:
            logging.error(f"Alert creation failed, status code: {response.status_code}, message: {response.text}")
            return False, None
    except Exception as e:
        logging.error(f"Error submitting alert: {e}")
        return False, None

def create_alert(alert_data, alert_id):
    try:
        alert = build_alert(alert_data, alert_id)
        submitted, submit_response = submit_alert(alert)
        if submitted:
            logging.info(f"Alert {alert_id} successfully processed and submitted.")
            hash_data_string = alert_data.get('all_fields_data_win_eventdata_hashes', '')
            hash_data = parse_hash_data(hash_data_string)
            found_hashes = search_hashes_in_misp(hash_data)
            observables = alert.artifacts
            if found_hashes:
                create_case_from_alert(alert, found_hashes, observables)
        else:
            logging.error(f"Failure in processing or submitting alert {alert_id}")
        return submit_response
    except Exception as e:
        logging.error(f"Exception in create_alert for {alert_id}: {e}")
        return None

def create_case_from_alert(alert, found_hashes, observables):
    """ Create a case in TheHive from an alert including observables. """
    if not found_hashes:
        logging.info("No matching hashes found in MISP, case creation not triggered.")
        return None

    try:
        hash_details = '\n'.join([f"Found {hash_info['type']}: {hash_info['value']} in MISP" for hash_info in found_hashes])
        case_description = f"{alert.description}\n\n**Hash Matches Found in MISP:**\n{hash_details}"
        
        # Initialize observables list for the case
        case_observables = [AlertArtifact(dataType=ob.dataType, data=ob.data, tags=ob.tags) for ob in observables]
        
        case = Case(
            title=alert.title,
            description=case_description,
            severity=alert.severity,
            tlp=alert.tlp,
            tags=alert.tags + ['MISP match found'],
            tasks=[{'title': 'Investigate MISP matches', 'status': 'InProgress'}],
            observables=case_observables
        )
        response = thehive_api.create_case(case)
        if response.status_code == 201:
            logging.info(f"Case successfully created from alert {alert.sourceRef}")
            return response
        else:
            logging.error(f"Failed to create case, status code: {response.status_code}, message: {response.text}")
            return None
    except Exception as e:
        logging.error(f"Exception when creating case from alert {alert.sourceRef}: {e}")
        return None
