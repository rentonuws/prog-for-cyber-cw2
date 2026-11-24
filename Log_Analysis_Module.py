import re

def analyse_apache_log(log_file):
    total_events = 0
    error_404_count = 0
    ip_address = set()
    apache_log = re.compile(
        r'(\d+\.\d+\.\d+\.\d+).*?"[^"]*"zs(\d{3})'
    )

    with open("apache_access.log", "r") as file:
        for line in file:
            total_events = total_events + 1
            match = apache_log.search(line)
            if match:
                ip = match.group(1)
                status_code = match.group(2)
                ip_address.add(ip)
                if status_code == "404":
                    error_404_count = error_404_count + 1
    return total_events,ip_address,error_404_count

def analyse_firewall_log(log_file):
    total_events = 0
    allowed_count = 0
    denied_count = 0
    ip_address = set()
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    with open("firewall.log", "r") as file:
        for line in file:
            total_events = total_events + 1
            ips = ip_pattern.findall(line)
            for ip in ips:
                ip_address.add(ip)
            uppercase_line = line.upper()
            if "ALLOW" in uppercase_line:
                allowed_count = allowed_count + 1
            elif "DENY" in uppercase_line:
                denied_count = denied_count + 1
    return (total_events,ip_address,allowed_count,denied_count)

def display_results(appach_total,firewall_total,unique_ips, error_404, allowed, denied):
    print("\n" + "=" * 60)
    print("LOG ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Total events in Apache log : {appach_total}")
    print(f"Total events in Firewall log : {firewall_total}")
    print(f"Total unique IP addresses : {len(unique_ips)}")
    print(f"Number of HTTP 404 events : {error_404}")
    print(f"Allowed Firewall connections : {allowed}")
    print(f"Denied firewall connections : {denied}")
    print("=" * 60)

def main():

    apache_log = "apache_access.log"
    firewall_log = "firewall.log"
    apache_total, apache_ips, error_404 = analyse_apache_log(apache_log)
    (firewall_total,firewall_ips,allowed,denied) = analyse_firewall_log(firewall_log)
    unique_ips = apache_ips.union(firewall_ips)
    display_results(apache_total,firewall_total,unique_ips,error_404,allowed,denied)

if __name__ == "__main__":
    main()

