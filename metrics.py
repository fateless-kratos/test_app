import time
from functools import wraps
from logger_setup import logger

class DialogflowMetrics:
    def __init__(self):
        self.api_calls = 0
        self.successful_calls = 0
        self.failed_calls = 0
        self.avg_response_time = 0
        self.total_response_time = 0
    
    def increment_api_calls(self):
        self.api_calls += 1
        logger.info(f"Total Dialogflow API calls: {self.api_calls}")
    
    def record_success(self, response_time):
        self.successful_calls += 1
        self.total_response_time += response_time
        self.avg_response_time = self.total_response_time / self.successful_calls
        logger.info(f"Successful Dialogflow calls: {self.successful_calls}, Avg response time: {self.avg_response_time:.2f}s")
    
    def record_failure(self):
        self.failed_calls += 1
        logger.warning(f"Failed Dialogflow calls: {self.failed_calls}")
    
    def get_metrics(self):
        return {
            "api_calls": self.api_calls,
            "successful_calls": self.successful_calls,
            "failed_calls": self.failed_calls,
            "avg_response_time": self.avg_response_time
        }

# Create global metrics instance
metrics = DialogflowMetrics()

# Decorator to track API calls and timing
def track_dialogflow_call(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        metrics.increment_api_calls()
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            metrics.record_success(time.time() - start_time)
            return result
        except Exception as e:
            metrics.record_failure()
            raise e
    return wrapper
