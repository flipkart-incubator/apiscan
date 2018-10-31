import logging
import os

if os.getcwd().split('/')[-1] == 'API':
    path = '../logs/scan.log'
else:
    path = 'logs/scan.log'

logger = logging.getLogger()
fh = logging.FileHandler(path)
logger.addHandler(fh)
logger.setLevel(logging.INFO)
