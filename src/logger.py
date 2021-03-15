import logging


def setup_logger(log_level="INFO"):
    logger = logging.getLogger(__name__)
    log_handler = logging.StreamHandler()
    logger.setLevel(log_level)
    log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    log_handler.setFormatter(log_format)
    logger.addHandler(log_handler)
    return logger
