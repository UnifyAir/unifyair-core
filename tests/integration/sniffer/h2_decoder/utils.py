import logging

_handler = logging.StreamHandler()
logger = logging.getLogger("h2_decoder")
logger.propagate = False
logger.addHandler(_handler)
