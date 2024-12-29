# config.py

import logging

def setup_logging():
    logging.basicConfig(filename='logs/alerts.log', level=logging.INFO, format='%(asctime)s - %(message)s')
