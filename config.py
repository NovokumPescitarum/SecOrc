from dotenv import load_dotenv
import os

load_dotenv()  # Load environment variables

class Config:
    THEHIVE_URL = os.getenv('THEHIVE_URL')
    THEHIVE_KEY = os.getenv('THEHIVE_KEY')
    MISP_URL = os.getenv('MISP_URL')
    MISP_KEY = os.getenv('MISP_KEY')
    MISP_VERIFYCERT = False if os.getenv('MISP_VERIFYCERT') == 'False' else True
