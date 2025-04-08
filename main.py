import json
import os
import socket
from datetime import datetime
from Agents.ammar import Ammar
from Agents.hassan import Hassan
from Agents.kofahi import Kofahi
from Agents.rakan import Rakan
from Agents.salah import Salah
from Agents.sajed import Sajed
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get Azure OpenAI configuration from environment variables
API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
DEPLOYMENT_NAME = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME")

if not all([API_KEY, AZURE_ENDPOINT, DEPLOYMENT_NAME]):
    raise ValueError("Missing required Azure OpenAI configuration in environment variables")

# Default scanning parameters
DEFAULT_SCAN_PARAMS = {
    "scan_type": "comprehensive",
    "ports": [80, 443, 8080, 8443,5432,8000,5433,3306,22,21,23,445,1433,1521,1434,5900,9090,9091,9092,9093,9094,9095,3389,5900 ,3306,69,445,25,110,143,5353],
    "vulnerability_types": ["sql_injection", "xss", "csrf", "rce"],
    "timeout": 30,
    "max_retries": 3
}

def resolve_domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        print(f"Could not resolve {domain}")
        return None

def initialize_log_file(domain, target_ip, scan_description):
    # Create domain-specific directory
    domain_dir = os.path.join("./Scans", domain)
    os.makedirs(domain_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    log_file_name = f"log-{timestamp}.json"
    log_file_path = os.path.join(domain_dir, log_file_name)
    
    log_data = {
        "domain": domain,
        "target_ip": target_ip,
        "scan_description": scan_description,
        "scan_parameters": DEFAULT_SCAN_PARAMS,
        "output": []
    }
    
    with open(log_file_path, "w") as log_file:
        json.dump(log_data, log_file, indent=2)
    
    return log_file_path, domain_dir

def process_domain(site_config, agents):
    domain = site_config["domain"]
    print(f"\nProcessing domain: {domain}")
    
    # Resolve domain to IP
    target_ip = resolve_domain_to_ip(domain)
    if not target_ip:
        print(f"Skipping {domain} - Could not resolve IP address")
        return
    
    print(f"Resolved IP: {target_ip}")
    
    # Create scan description based on site configuration
    scan_description = f"""
    Target: {domain}
    Description: {site_config['description']}
    Scan Type: {DEFAULT_SCAN_PARAMS['scan_type']}
    Ports to Scan: {', '.join(map(str, DEFAULT_SCAN_PARAMS['ports']))}
    Vulnerability Types: {', '.join(DEFAULT_SCAN_PARAMS['vulnerability_types'])}
    Timeout: {DEFAULT_SCAN_PARAMS['timeout']} seconds
    Max Retries: {DEFAULT_SCAN_PARAMS['max_retries']}
    """
    
    # Initialize logging for this domain
    log_file_path, domain_dir = initialize_log_file(domain, target_ip, scan_description)
    
    findings = []
    
    print("Initial Strategy:")
    strategy = agents['ammar'].generate_strategy(target_ip, scan_description, log_file_path=log_file_path)
    findings.append({"strategy": strategy})

    while True:
        reviewed_strategy = agents['hassan'].review_strategy(strategy, scan_description, log_file_path=log_file_path)
        findings.append({"reviewed_strategy": reviewed_strategy})

        if reviewed_strategy["approved"]:
            commands = strategy["strategy"]
            output = agents['salah'].execute_commands(commands, target_ip, scan_description, agents['kofahi'], agents['ammar'], agents['rakan'], log_file_path=log_file_path)
            print("Command Output:")
            print(output)
            findings.append({"commands": commands, "output": output})
            print("Hassan's Thoughts on the scan result:")
            hassan_assessment = agents['hassan'].review_output(output, scan_description, log_file_path=log_file_path)
            findings.append({"hassan_assessment": hassan_assessment})

            if hassan_assessment["satisfactory"]:
                print("Scan completed. Client's requirements have been met.")
                break
            else:
                feedback = hassan_assessment["feedback"]
                strategy = agents['ammar'].generate_strategy(target_ip, scan_description, feedback=feedback, log_file_path=log_file_path)
                findings.append({"updated_strategy_based_on_feedback": strategy})
                print("Updated strategy based on Hassan's feedback:")
        else:
            feedback = reviewed_strategy["feedback"]
            print("Hassan's feedback:")
            print("Updated strategy based on Hassan's feedback:")
            strategy = agents['ammar'].generate_strategy(target_ip, scan_description, feedback=feedback, log_file_path=log_file_path)
            findings.append({"updated_strategy_based_on_feedback": strategy})

    # Save findings in domain-specific directory
    findings_file = os.path.join(domain_dir, "findings.json")
    with open(findings_file, "w") as f:
        json.dump(findings, f, indent=2)

    print("Findings Report:")
    report = agents['sajed'].generate_report(target_ip, scan_description, findings_file, log_file_path=log_file_path)

    while True:
        hassan_review = agents['hassan'].review_report(report, log_file_path=log_file_path)
        findings.append({"hassan_review": hassan_review})
        print("Hassan's Review:")
        if hassan_review["Report Approval"]:
            print("Findings report has been approved by Hassan.")
            break
        else:
            feedback = hassan_review["feedback"]
            print("Hassan's feedback:")
            report = agents['sajed'].generate_report(target_ip, scan_description, findings_file, feedback=feedback, log_file_path=log_file_path)
            print("Updated Findings Report:")

    report_file = os.path.join(domain_dir, "findings_report.md")
    with open(report_file, "w") as f:
        f.write(report)
    print(f"Findings report saved as {report_file}")

def main():
    # Create main Scans directory
    os.makedirs("./Scans", exist_ok=True)
    
    # Load configuration from JSON file
    try:
        with open("config.json", "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        print("Error: config.json file not found")
        return
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in config.json")
        return
    
    if not config.get("sites"):
        print("Error: No sites found in config.json")
        return
    
    # Initialize agents
    agents = {
        'ammar': Ammar(api_key=API_KEY, azure_endpoint=AZURE_ENDPOINT, deployment_name=DEPLOYMENT_NAME),
        'hassan': Hassan(api_key=API_KEY, azure_endpoint=AZURE_ENDPOINT, deployment_name=DEPLOYMENT_NAME),
        'kofahi': Kofahi(api_key=API_KEY, azure_endpoint=AZURE_ENDPOINT, deployment_name=DEPLOYMENT_NAME),
        'rakan': Rakan(api_key=API_KEY, azure_endpoint=AZURE_ENDPOINT, deployment_name=DEPLOYMENT_NAME),
        'salah': Salah(api_key=API_KEY, azure_endpoint=AZURE_ENDPOINT, deployment_name=DEPLOYMENT_NAME),
        'sajed': Sajed(api_key=API_KEY, azure_endpoint=AZURE_ENDPOINT, deployment_name=DEPLOYMENT_NAME)
    }
    
    # Process each site
    for site in config["sites"]:
        process_domain(site, agents)

if __name__ == '__main__':
    main()
