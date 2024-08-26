from prometheus_client import Counter, Histogram, Gauge
from django.db import connection

# Existing metrics
api_requests_total = Counter('api_requests_total', 'Total API requests', ['method', 'endpoint'])
api_response_time = Histogram('api_response_time_seconds', 'API response time in seconds', ['method', 'endpoint'])
db_query_duration = Histogram('db_query_duration_seconds', 'Database query duration in seconds')

# New metrics
api_errors_total = Counter('api_errors_total', 'Total API errors', ['method', 'endpoint', 'status'])
api_in_progress = Gauge('api_in_progress', 'Number of API requests in progress')

def record_api_metrics(request, response, response_time):
    method = request.method
    endpoint = request.path
    api_requests_total.labels(method=method, endpoint=endpoint).inc()
    api_response_time.labels(method=method, endpoint=endpoint).observe(response_time)
    
    if 400 <= response.status_code < 600:
        api_errors_total.labels(method=method, endpoint=endpoint, status=response.status_code).inc()

class APIMetricsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        api_in_progress.inc()
        try:
            response = self.get_response(request)
            return response
        finally:
            api_in_progress.dec()

class DatabaseMetricsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        for query in connection.queries:
            db_query_duration.observe(float(query['time']))
        
        return response