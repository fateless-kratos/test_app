import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler
from config import Config

# Configure logging
def setup_logger():
    """Set up the application logger"""
    # Get log level from config
    log_level_str = os.environ.get('LOG_LEVEL', 'INFO').upper()
    log_level = getattr(logging, log_level_str, logging.INFO)
    
    # Create logger
    logger = logging.getLogger('slack_dialogflow')
    logger.setLevel(log_level)
    
    # Create formatter with more detail
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    )
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Create file handler for persistent logs
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, 'slack_dialogflow.log')
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=10*1024*1024,  # 10 MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Add request ID to log record
    class RequestIDFilter(logging.Filter):
        def filter(self, record):
            record.request_id = getattr(record, 'request_id', '-')
            return True
            
    logger.addFilter(RequestIDFilter())
    
    return logger

logger = setup_logger()

# Add a utility to log incoming requests with timing
def log_request(func):
    """Decorator to log incoming requests with timing"""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        request_id = f"req_{int(start_time * 1000)}"
        
        # Add request ID to thread local storage or similar
        extra = {'request_id': request_id}
        logger.info(f"Processing request {request_id}", extra=extra)
        
        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time
            logger.info(f"Request {request_id} completed in {elapsed:.3f}s", extra=extra)
            return result
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"Request {request_id} failed after {elapsed:.3f}s: {str(e)}", 
                        exc_info=True, extra=extra)
            raise
            
    return wrapper
