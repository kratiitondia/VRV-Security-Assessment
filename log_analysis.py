import re
import csv
from collections import Counter
import matplotlib.pyplot as plt

# Function to parse log file
def parse_log_file(file_path):
    log_data = []
    pattern = r'(\d+\.\d+\.\d+\.\d+).*\"(\w+)\s([^\s]+)\sHTTP.*\"\s(\d+)'

    with open(file_path, 'r') as file:
        for line in file:
            match = re.search(pattern, line)
            if match:
                ip_address = match.group(1)
                method = match.group(2)
                endpoint = match.group(3)
                status_code = match.group(4)
                log_data.append((ip_address, method, endpoint, status_code))

    return log_data

# Function to count requests by IP address
def count_requests_by_ip(log_data):
    ip_addresses = [entry[0] for entry in log_data]
    ip_count = Counter(ip_addresses)
    return sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

# Function to find the most requested endpoint
def find_most_requested_endpoint(log_data):
    endpoints = [entry[2] for entry in log_data]
    endpoint_count = Counter(endpoints)
    return endpoint_count

# Function to count HTTP status codes
def count_status_codes(log_data):
    status_codes = [entry[3] for entry in log_data]
    status_count = Counter(status_codes)
    return status_count

# Function to detect suspicious activity
def detect_suspicious_activity(log_data):
    failed_logins = [entry[0] for entry in log_data if entry[3] == '401']
    failed_login_count = Counter(failed_logins)
    return sorted(failed_login_count.items(), key=lambda x: x[1], reverse=True)

# Function to save results to a CSV file
def save_results_to_csv(ip_counts, endpoint_counts, suspicious_activity):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_counts)

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerows(endpoint_counts.items())

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activity)

# Function to generate visualizations
def generate_visual_reports(ip_counts, endpoint_counts, status_counts):
    # IP Address Requests
    ip_labels, ip_values = zip(*ip_counts)
    plt.figure(figsize=(10, 6))
    plt.bar(ip_labels, ip_values, color='skyblue')
    plt.title('Requests per IP Address')
    plt.xlabel('IP Address')
    plt.ylabel('Request Count')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('requests_per_ip.png')
    plt.show()

    # Most Accessed Endpoints
    endpoint_labels, endpoint_values = zip(*endpoint_counts.items())
    plt.figure(figsize=(10, 6))
    plt.bar(endpoint_labels, endpoint_values, color='lightgreen')
    plt.title('Most Accessed Endpoints')
    plt.xlabel('Endpoint')
    plt.ylabel('Access Count')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('most_accessed_endpoints.png')
    plt.show()

    # HTTP Status Codes
    status_labels, status_values = zip(*status_counts.items())
    plt.figure(figsize=(6, 6))
    plt.pie(status_values, labels=status_labels, autopct='%1.1f%%', startangle=140, colors=plt.cm.Paired.colors)
    plt.title('HTTP Status Codes')
    plt.savefig('http_status_codes.png')
    plt.show()

# Function to display results in the terminal
def display_results(ip_counts, endpoint_counts, suspicious_activity):
    print("Requests per IP Address:")
    print("=======================")
    for ip, count in ip_counts:
        print(f"{ip:20} {count}")
    print()

    print("Most Accessed Endpoints:")
    print("========================")
    for endpoint, count in endpoint_counts.items():
        print(f"{endpoint:20} {count}")
    print()

    print("Suspicious Activity:")
    print("====================")
    for ip, count in suspicious_activity:
        print(f"{ip:20} {count}")

# Main script execution
if __name__ == "__main__":
    log_file = 'sample.log'  # Update this to the path of your log file

    # Parse the log file
    parsed_data = parse_log_file(log_file)

    # Analyze requests per IP
    ip_counts = count_requests_by_ip(parsed_data)

    # Find the most requested endpoint
    endpoint_counts = find_most_requested_endpoint(parsed_data)

    # Count HTTP status codes
    status_counts = count_status_codes(parsed_data)

    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(parsed_data)

    # Save results to CSV
    save_results_to_csv(ip_counts, endpoint_counts, suspicious_activity)

    # Display results in terminal
    display_results(ip_counts, endpoint_counts, suspicious_activity)

    # Generate visual reports
    generate_visual_reports(ip_counts, endpoint_counts, status_counts)

    print("Results saved to log_analysis_results.csv and visual reports generated.")
