from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, Case
from config import Config
from misp import search_hashes_in_misp
from utils import parse_hash_data
import logging

thehive_api = TheHiveApi(Config.THEHIVE_URL, Config.THEHIVE_KEY)

def build_alert(alert_data, alert_id):
    """ Build the alert object with detailed descriptions based on alert data. """
    severity_map