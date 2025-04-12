import json
import pexpect
import time
from agent import Agent
import subprocess
import os

class Salah(Agent):
    def __init__(self, api_key, azure_endpoint=None, deployment_name=None):
        super().__init__("Salah", api_key, azure_endpoint, deployment_name)
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
            "agent": "Salah",
            "request": message,
            "timestamp": time.time()
        }
        self.write_communication(communication)
        return self.read_communication()

    def execute_commands(self, commands, target_ip, scan_description, kofahi, ammar, rakan, log_file_path=None):
        output = ""
        executed_commands = []
        pending_commands = commands.copy()
        command_index = 0
        
        while command_index < len(commands):
            command = commands[command_index]
            try:
                output += f"Executing command: {command}\n"
                child = pexpect.spawn(command, timeout=300, encoding='utf-8')
                print(output)
                executed_commands.append(command)
                pending_commands = commands[command_index+1:]
                
                command_output = ""
                start_time = time.time()
                while True:
                    try:
                        child.expect('\r\n')
                        output_line = child.before
                        command_output += output_line + "\n"
                        
                        elapsed_time = time.time() - start_time
                        if elapsed_time >= 10:
                            rakan_response = rakan.monitor_output(target_ip, scan_description, command_output, executed_commands, pending_commands, log_file_path)
                            if rakan_response["input_needed"]:
                                ammar_response = ammar.generate_input(target_ip, scan_description, command_output, pending_commands, log_file_path)
                                input_command = ammar_response["input"]
                                
                                if input_command:
                                    command_index += 1
                                    print(f"Input: {input_command}")
                                    child.sendline(input_command)
                                else:
                                    # Request additional information if needed
                                    response = self.request_additional_info({
                                        "context": "Input needed but not generated",
                                        "command_output": command_output,
                                        "pending_commands": pending_commands
                                    })
                                    if response and "input" in response:
                                        child.sendline(response["input"])
                                    else:
                                        command_index += 1
                                        break
                            start_time = time.time()
                            command_output = ""
                            
                    except pexpect.TIMEOUT:
                        output_line = child.before
                        print(output_line)
                        command_output += output_line + "\n"
                        
                    except pexpect.EOF:
                        output_line = child.before
                        print(output_line)
                        command_output += output_line + "\n"
                        output += command_output
                        command_index += 1
                        break
                    
            except pexpect.exceptions.ExceptionPexpect as e:
                error_message = f"Error executing command: {command}\nError message: {str(e)}\n\n"
                context = f"Target IP: {target_ip}\nScan Description: {scan_description}\nCommand Output:\n{output}"
                kofahi_response = kofahi.handle_error(error_message, context, log_file_path)
                self.add_to_chat_history("Kofahi", "user", f"Error Message:\n{error_message}\n\nContext:\n{context}")
                self.add_to_chat_history("Kofahi", "assistant", json.dumps(kofahi_response))
                print("Error encountered. Kofahi's response:")
                print(json.dumps(kofahi_response, indent=2))
                if "fix" in kofahi_response:
                    fix_commands = kofahi_response["fix"]
                    print("Executing fix commands:")
                    for fix_command in fix_commands:
                        print(f"Executing command: {fix_command}")
                        try:
                            fix_output = subprocess.check_output(fix_command, shell=True, universal_newlines=True)
                            print(f"Command output: {fix_output}")
                        except subprocess.CalledProcessError as e:
                            print(f"Error executing fix command: {fix_command}")
                            print(f"Error message: {e.output}")
                output += error_message
                command_index += 1
                
        return output