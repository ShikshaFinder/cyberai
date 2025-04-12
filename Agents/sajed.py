import json
from agent import Agent
import os
import time

class Sajed(Agent):
    def __init__(self, api_key, azure_endpoint=None, deployment_name=None):
        super().__init__("Sajed", api_key, azure_endpoint, deployment_name)
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
            "agent": "Sajed",
            "request": message,
            "timestamp": time.time()
        }
        self.write_communication(communication)
        return self.read_communication()

    def generate_report(self, target_ip, scan_description, findings_file, feedback=None, log_file_path=None):
        with open(findings_file, "r") as f:
            findings = json.load(f)

        system_message = "You are Sajed, an expert findings report writer. Your role is to generate a comprehensive and professional findings report based on the provided JSON file containing the vulnerability scan findings. The report should include an appropriate title, an executive summary, detailed findings for each vulnerability, and recommendations for remediation. Structure the report in a clear and concise manner, using Markdown formatting."
        
        user_message = f"Target IP: {target_ip}\nScan Description: {scan_description}\nFindings File: {json.dumps(findings, indent=2)}\n\nPlease generate a comprehensive findings report based on the provided vulnerability scan findings. Use Markdown formatting for the report."
        
        if feedback:
            user_message += f"\n\nFeedback from Hassan: {feedback}\n\nPlease update the findings report based on the provided feedback, ensuring that the report is comprehensive, professional, and addresses all the necessary aspects."

        # Check if additional information is needed
        if not findings or len(findings) == 0:
            response = self.request_additional_info({
                "context": "No findings available",
                "target_ip": target_ip,
                "scan_description": scan_description
            })
            if response and "findings" in response:
                findings = response["findings"]
                user_message = f"Target IP: {target_ip}\nScan Description: {scan_description}\nFindings File: {json.dumps(findings, indent=2)}\n\nPlease generate a comprehensive findings report based on the provided vulnerability scan findings. Use Markdown formatting for the report."

        report = self.generate_response("Hassan", user_message, system_message)
        self.add_to_chat_history("Hassan", "user", user_message)
        self.add_to_chat_history("Hassan", "assistant", report)
        self.print_agent_output(text=report, log_file_path=log_file_path)
        return report.strip()