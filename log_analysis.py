import csv
from collections import Counter, defaultdict

# Configuration
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10


def parse_log_file(file_name):
    """Parse the log file to extract IPs, endpoints, and failed login attempts."""
    ip_requests = Counter()
    endpoint_access = Counter()
    failed_logins = defaultdict(int)

    with open(file_name, "r") as file:
        for line in file:
            parts = line.split()
            ip = parts[0]
            endpoint = parts[6]
            status_code = parts[8]
            message = " ".join(parts[9:])

            # Count requests per IP
            ip_requests[ip] += 1

            # Count endpoint accesses
            endpoint_access[endpoint] += 1

            # Detect failed login attempts
            if status_code == "401" or "Invalid credentials" in message:
                failed_logins[ip] += 1

    return ip_requests, endpoint_access, failed_logins


def analyze_log_data(ip_requests, endpoint_access, failed_logins):
    """Analyze data to determine the most accessed endpoint and suspicious IPs."""
    most_accessed = endpoint_access.most_common(1)
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    return most_accessed, suspicious_ips


def save_to_csv(ip_requests, most_accessed, suspicious_ips, output_file):
    """Save the results into a CSV file."""
    with open(output_file, mode="w", newline="") as file:
        writer = csv.writer(file)

        # Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        writer.writerow([])  # Blank line

        # Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        if most_accessed:
            endpoint, count = most_accessed[0]
            writer.writerow([endpoint, count])

        writer.writerow([])  # Blank line

        # Suspicious Activity
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


def main():
    """Main execution function."""
    print("Analyzing log file...")

    # Parse log file
    ip_requests, endpoint_access, failed_logins = parse_log_file(LOG_FILE)

    # Analyze data
    most_accessed, suspicious_ips = analyze_log_data(ip_requests, endpoint_access, failed_logins)

    # Display results in the terminal
    print("\nIP Address Request Counts:")
    print("IP Address           Request Count")
    for ip, count in ip_requests.items():
        print(f"{ip:20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed:
        endpoint, count = most_accessed[0]
        print(f"{endpoint} (Accessed {count} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:20} {count}")

    # Save results to CSV
    save_to_csv(ip_requests, most_accessed, suspicious_ips, OUTPUT_FILE)
    print(f"\nResults saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
