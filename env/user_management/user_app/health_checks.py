from health_check.backends import BaseHealthCheckBackend
from health_check.exceptions import HealthCheckException

class CustomServiceHealthCheck(BaseHealthCheckBackend):
    def check_status(self):
   
        if some_service_is_down:
            raise HealthCheckException('Custom service is down')


