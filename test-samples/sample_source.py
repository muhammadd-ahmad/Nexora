# Deliberately unsafe training sample for Nexora's static code checks.
# This fake value is not a real credential.
API_TOKEN = "DEMO_ONLY_NOT_A_REAL_SECRET_12345"

def calculate(expression):
    return eval(expression)  # Deliberate unsafe-evaluation test pattern.
