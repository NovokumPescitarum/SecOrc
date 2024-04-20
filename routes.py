from flask import request
from utils import extract_data
from thehive import create_alert  # Ensuring correct import
import logging
from flask import jsonify
import uuid

def configure_routes(app):
    @app.route('/webhook', methods=['POST'])
    def handle_webhook():
        logging.info("Received webhook request")
        if not request.json:
            logging.error("No JSON received")
            return jsonify({'error': 'No JSON data received'}), 400
        
        data = request.json
        extracted_data = extract_data(data)

        # Generate a unique ID if not present
        alert_id = extracted_data.get('id', str(uuid.uuid4()))
        logging.info(f"Processing alert with ID: {alert_id}")

        response = create_alert(extracted_data, alert_id)
        if response:
            return jsonify({'message': 'Alert processed successfully', 'alert_id': alert_id}), 200
        else:
            logging.error("Failed to process alert")
            return jsonify({'error': 'Failed to process alert'}), 500

