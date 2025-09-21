import requests
import time
import json

def test_platform():
    base_url = "http://localhost:8000"
    
    # Test 1: Health check
    print("Testing health check...")
    response = requests.get(f"{base_url}/health")
    print(f"Health check: {response.status_code}")
    
    # Test 2: Status
    print("Testing status...")
    response = requests.get(f"{base_url}/status")
    print(f"Status: {response.status_code}")
    
    # Test 3: Generate test alert
    print("Testing alert generation...")
    response = requests.post(f"{base_url}/test/alert")
    print(f"Test alert: {response.status_code}")
    
    # Test 4: Generate test traces
    print("Testing trace generation...")
    response = requests.post(f"{base_url}/test/traces", 
                           json={"count": 20})
    print(f"Test traces: {response.status_code}")
    
    print("All tests completed!")

if __name__ == "__main__":
    test_platform()