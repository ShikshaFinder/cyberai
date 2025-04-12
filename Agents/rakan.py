import json
from agent import Agent
import os
import time

class Rakan(Agent):
    def __init__(self, api_key, azure_endpoint=None, deployment_name=None):
        super().__init__("Rakan", api_key, azure_endpoint, deployment_name)
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
            "agent": "Rakan",
            "request": message,
            "timestamp": time.time()
        }
        self.write_communication(communication)
        return self.read_communication()

    def monitor_output(self, target_ip, scan_description, command_output, executed_commands, pending_commands, log_file_path=None):
        system_message = "You are Rakan, an expert in monitoring command execution output. Your role is to analyze the provided command output and determine if the executed command requires input or if it is still running a previous command or loading up. If input is required, indicate that it is time to provide input. If the command is still running or loading up, indicate that no input is needed at the moment. Respond with your analysis in JSON format, using the 'input_needed' key as a boolean value."
        
        user_message = f"Target IP: {target_ip}\nScan Description: {scan_description}\nCommand Output:\n{command_output}\nExecuted Commands: {json.dumps(executed_commands)}\nPending Commands: {json.dumps(pending_commands)}\n\nAnalyze the command output and determine if input is required or if the command is still running or loading up. Respond with your analysis in JSON format, using the 'input_needed' key as a boolean value."
        
        # Check if additional information is needed for analysis
        if not command_output or len(command_output.strip()) == 0:
            response = self.request_additional_info({
                "context": "No command output available",
                "target_ip": target_ip,
                "scan_description": scan_description,
                "executed_commands": executed_commands,
                "pending_commands": pending_commands
            })
            if response and "command_output" in response:
                command_output = response["command_output"]
                user_message = f"Target IP: {target_ip}\nScan Description: {scan_description}\nCommand Output:\n{command_output}\nExecuted Commands: {json.dumps(executed_commands)}\nPending Commands: {json.dumps(pending_commands)}\n\nAnalyze the command output and determine if input is required or if the command is still running or loading up. Respond with your analysis in JSON format, using the 'input_needed' key as a boolean value."

        rakan_response = self.generate_response("Salah", user_message, system_message, response_format={"type": "json_object"})
        self.add_to_chat_history("Salah", "user", user_message)
        self.add_to_chat_history("Salah", "assistant", rakan_response)
        self.print_agent_output(text=rakan_response, log_file_path=log_file_path)
        return json.loads(rakan_response)