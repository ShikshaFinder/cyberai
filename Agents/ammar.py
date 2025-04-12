import json
from agent import Agent
import os
import time

class Ammar(Agent):
    def __init__(self, api_key, azure_endpoint=None, deployment_name=None):
        super().__init__("Ammar", api_key, azure_endpoint, deployment_name)
        self.com_file = "com.json"
        self.environment_requirements = {
            "auth_tokens": [],
            "external_services": []
        }

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

    def check_environment_requirements(self):
        """Check if all environment requirements are met"""
        missing_requirements = []
        
        # Check auth tokens
        for token in self.environment_requirements["auth_tokens"]:
            if not os.getenv(token):
                missing_requirements.append({
                    "type": "auth_token",
                    "name": token,
                    "description": f"Authentication token for {token} is required"
                })
        
        # Check external services
        for service in self.environment_requirements["external_services"]:
            if not os.getenv(service):
                missing_requirements.append({
                    "type": "external_service",
                    "name": service,
                    "description": f"External service {service} is required"
                })
        
        return missing_requirements

    def request_additional_info(self, message):
        """Request additional information through com.json"""
        # First check environment requirements
        missing_requirements = self.check_environment_requirements()
        if missing_requirements:
            communication = {
                "agent": "Ammar",
                "request": {
                    "type": "environment_requirements",
                    "context": "Missing environment requirements",
                    "details": {
                        "missing_requirements": missing_requirements
                    }
                },
                "timestamp": time.time()
            }
            self.write_communication(communication)
            response = self.read_communication()
            
            # If environment requirements are provided in response, update environment
            if response and "environment" in response:
                env_data = response["environment"]
                for token in env_data.get("auth_tokens", {}):
                    os.environ[token] = env_data["auth_tokens"][token]
                for service in env_data.get("external_requirements", {}):
                    os.environ[service] = env_data["external_requirements"][service]
            
            # Recheck requirements after potential updates
            missing_requirements = self.check_environment_requirements()
            if missing_requirements:
                return None

        # If all requirements are met, proceed with the original request
        communication = {
            "agent": "Ammar",
            "request": {
                "type": "additional_info",
                "context": message.get("context", ""),
                "details": message
            },
            "timestamp": time.time()
        }
        self.write_communication(communication)
        return self.read_communication()

    def generate_strategy(self, target_ip, scan_description, approved_strategy=None, feedback=None, log_file_path=None):
        # Add required environment variables
        self.environment_requirements["auth_tokens"].extend([
            "API_KEY",
            "AZURE_ENDPOINT"
        ])
        self.environment_requirements["external_services"].extend([
            "SCANNER_API_ENDPOINT"
        ])

        system_message = "You are Ammar, an experienced penetration tester. Your role is to generate a comprehensive strategy to conduct a successful and comprehensive vulnerability scan based on the provided target IP and scan description. The strategy should include a set of relevant Linux terminal commands to gather information and detect potential vulnerabilities. Respond with the strategy in JSON format, using the 'strategy' key as an array of command strings. Ensure the commands are tailored to the specific target and scan description, and are ready to be executed without any manual modifications. Include any necessary explanation or context in the 'description' key. Always start with recon, and ask Hassan, the senior what command should you execute next based on the result. Note, Always include your name and role at the end of each Description."
        
        user_message = f"Target IP: {target_ip}\nScan Description: {scan_description}\n\nGenerate a comprehensive strategy to complete the vulnerability scan based on the provided IP and description. Provide the strategy in JSON format, along with any relevant explanation or context. Ensure that all commands are complete and can be executed as-is without requiring manual changes. and send it to Hassa, Your senior for review. Always include your name and role at the end of each Description."
        
        if approved_strategy:
            user_message += f"\n\nApproved Strategy:\n{json.dumps(approved_strategy, indent=2)}\n\nPlease update the strategy based on the approved strategy, ensuring that all commands are complete and ready to be executed without modifications."
        elif feedback:
            user_message += f"\n\nFeedback from Hassan: {feedback}\n\nPlease update the strategy based on the provided feedback, ensuring that all commands are complete and ready to be executed without modifications. Return in JSON format."

        # Check if additional information is needed for strategy generation
        if not target_ip or not scan_description:
            response = self.request_additional_info({
                "context": "Insufficient target information",
                "target_ip": target_ip,
                "scan_description": scan_description
            })
            if response and "target_details" in response:
                target_ip = response["target_details"].get("target_ip", target_ip)
                scan_description = response["target_details"].get("scan_description", scan_description)
                user_message = f"Target IP: {target_ip}\nScan Description: {scan_description}\n\nGenerate a comprehensive strategy to complete the vulnerability scan based on the provided IP and description. Provide the strategy in JSON format, along with any relevant explanation or context. Ensure that all commands are complete and can be executed as-is without requiring manual changes. and send it to Hassa, Your senior for review. Always include your name and role at the end of each Description."

        strategy = self.generate_response("Hassan", user_message, system_message, response_format={"type": "json_object"})
        self.print_agent_output(text=strategy, log_file_path=log_file_path)
        return json.loads(strategy)

    def generate_input(self, target_ip, scan_description, command_output, commands, log_file_path=None):
        system_message = "You are Ammar, an experienced penetration tester. Based on the provided command output, determine if the executed command requires input. If input is required, provide the next command from the given list of commands in the correct order. If no input is required or the output suggests the current task is complete, provide an empty string. Respond with the input in JSON format, using the 'input' key to provide the input string."
        
        user_message = f"Target IP: {target_ip}\nScan Description: {scan_description}\nCommand Output:\n{command_output}\nCommands: {json.dumps(commands)}\n\nBased on the command output, determine if input is required. If input is required, provide the next command from the given list of commands in the correct order. If no input is required or the output suggests the current task is complete, provide an empty string. Respond with the input in JSON format."
        
        # Check if additional information is needed for input generation
        if not command_output or not commands:
            response = self.request_additional_info({
                "context": "Insufficient command information",
                "command_output": command_output,
                "commands": commands
            })
            if response and "command_details" in response:
                command_output = response["command_details"].get("command_output", command_output)
                commands = response["command_details"].get("commands", commands)
                user_message = f"Target IP: {target_ip}\nScan Description: {scan_description}\nCommand Output:\n{command_output}\nCommands: {json.dumps(commands)}\n\nBased on the command output, determine if input is required. If input is required, provide the next command from the given list of commands in the correct order. If no input is required or the output suggests the current task is complete, provide an empty string. Respond with the input in JSON format."

        ammar_response = self.generate_response("Salah", user_message,system_message,response_format={"type": "json_object"})
        self.add_to_chat_history("Salah", "user", user_message)
        self.add_to_chat_history("Salah", "assistant", ammar_response)
        self.print_agent_output(text=ammar_response, log_file_path=log_file_path)
        return json.loads(ammar_response)