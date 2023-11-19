import subprocess
import random
import sys
import re
import os

argument_values = ['value1', 'value2']
argument = None

if len(sys.argv) != 2:
    print("Usage: python tests.py <execution|verdict>")
else:
    argument = sys.argv[1]
    if argument not in argument_values:
        print("Usage: python tests.py <execution|verdict>")
        exit(1)

to_write = "iteration,expected,result,exec_time\n"
for i in range(0, 1000):
    # List of strings as arguments
    source_ips = ["10.10.0.10", "10.10.0.11", "10.10.0.12", "10.10.0.20" ]
    target_ips = ["10.10.0.10:8080", "10.10.0.11:8080", "10.10.0.12:8080", "10.10.0.20:8080"]

    # Randomly select arguments
    target_ip = random.choice(target_ips)
    source_ips.remove(target_ip.split(':')[0])
    #source_ips = random.sample(source_ips, k=min(len(source_ips), 3))
    source_ip = random.choice(source_ips)

    current_path = os.getcwd()

    executable_path = f"{current_path}/measurement_programs/testFw_measure_{argument}.py"

    # Form the command to run the other Python script with sudo
    command = ["sudo", "python3", executable_path, source_ip, target_ip]
    # Run the command
    try:
        result = subprocess.run(command, capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        sys.exit(1)

    output_lines = result.stdout.splitlines()
    results_line = output_lines[-3].decode()
    preformance_line = output_lines[-1].decode()
    microseconds = float(re.search(r"\d+\.\d+", preformance_line).group())

    # Check if the last line contains "UNREACHABLE" or "REACHABLE"
    if "UNREACHABLE" in results_line:
        status = "UNREACHABLE"
    elif "REACHABLE" in results_line:
        status = "REACHABLE"
    else:
        status = "UNKNOWN"
        
    if target_ip == "10.10.0.20:8080" or target_ip == "10.10.0.10:8080" or source_ip == "10.10.0.11" or source_ip == "10.10.0.12":
        expected_status = "REACHABLE"
    elif target_ip == "10.10.0.11:8080":
        if source_ip == "10.10.0.10":
            expected_status = "UNREACHABLE"
        else:
            expected_status = "REACHABLE"
    elif target_ip == "10.10.0.12:8080":
        if source_ip == "10.10.0.20":
            expected_status = "UNREACHABLE"
        else:
            expected_status = "REACHABLE"

    to_write += f"{i+1},{expected_status},{status},{microseconds}\n"
    print(f"Progress: {((i / 1000) * 100):.2f}%", end='\r')

# Open a file in write mode
with open(f"{current_path}/results/tests_{argument}_measurement.csv", "w") as file:
    # Write the string to the file
    file.write(to_write)