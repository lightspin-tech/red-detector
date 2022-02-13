import logging


def setup_logger(id, log_level="INFO"):
    logger = logging.getLogger(__name__)
    log_handler = logging.StreamHandler()
    logger.setLevel(log_level)
    extra = {'id': id}
    log_format = logging.Formatter('%(asctime)s: [%(id)s] - %(levelname)s - %(message)s', )
    log_handler.setFormatter(log_format)
    logger.addHandler(log_handler)
    logger = logging.LoggerAdapter(logger, extra)
    logger = logging.LoggerAdapter(logger, extra)
    return logger
