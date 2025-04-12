import json
from agent import Agent
import os
import time

class Kofahi(Agent):
    def __init__(self, api_key, azure_endpoint=None, deployment_name=None):
        super().__init__("Kofahi", api_key, azure_endpoint, deployment_name)
        self.com_file = "com.json"

    def read_communication(self):
        """Read communication from com.json file"""
        if os.path.exists(self.com_file):
            try:
                with open(self.com_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {}
        return {}

    def write_communication(self, data):
        """Write communication to com.json file"""
        with open(self.com_file, 'w') as f:
            json.dump(data, f, indent=2)

    def request_additional_info(self, message):
        """Request additional information through com.json"""
        communication = {
            "agent": "Kofahi",
            "request": message,
            "timestamp": time.time()
        }
        self.write_communication(communication)
        return self.read_communication()

    def handle_error(self, error_message, context, log_file_path=None):
        system_message = "You are Kofahi, an experienced and expert in Linux OS. Your role is to provide quick fixes and explanations for errors encountered during the execution of commands. Respond with the fix in JSON format, using the 'fix' key as an array of command strings to be executed in the correct order, and the 'explanation' key to provide the reason for the error and any necessary context."
        
        user_message = f"Error Message:\n{error_message}\n\nContext:\n{context}\n\nPlease provide a quick fix for the encountered error, along with an explanation of the reason for the error. Respond with the fix in JSON format, including any necessary commands to be executed in the correct order."
        
        # Check if additional information is needed for error handling
        if not error_message or not context:
            response = self.request_additional_info({
                "context": "Insufficient error information",
                "error_message": error_message,
                "context": context
            })
            if response and "error_details" in response:
                error_message = response["error_details"].get("message", error_message)
                context = response["error_details"].get("context", context)
                user_message = f"Error Message:\n{error_message}\n\nContext:\n{context}\n\nPlease provide a quick fix for the encountered error, along with an explanation of the reason for the error. Respond with the fix in JSON format, including any necessary commands to be executed in the correct order."

        kofahi_response = self.generate_response("Salah", user_message, system_message, response_format={"type": "json_object"})
        self.print_agent_output(text=kofahi_response, log_file_path=log_file_path)
        return json.loads(kofahi_response)