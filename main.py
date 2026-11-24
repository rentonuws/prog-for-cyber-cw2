from log_analysis_module import log_analysis
from failed_login_module import analyse_apache_log

from config import report_file

valid = False
options = 0

while not valid:
    print("\n")
    print("=" *60)
    print("Threat intelligence and analysis tools")
    print("1. Log Analysis Moduel\n2. Failed login detection\n3. Running IP threat intelligence\4. File hash analysis\n5. Threat hunting\n6. Generate security report\n7. exit")
    options = input("Please choose an option from 1-7")
    if options == "1":
        log_analysis()
    elif options == "2":
        failed_login_detection()
    elif options == "3":
        ip_threat_intelligence(failed_login_results[suspicious_ips])
    elif options == "4":
        hash_analysis()
    elif options == "5":
        threat_hunting()
    elif options == "6":
        print("Generating Report...")
        generate_report(log_analysis(),failed_login_detection(),ip_threat_intelligence(failed_login_results[suspicious_ip],hash_analysis(),threat_hunting()))
        print("\n"+ "=" * 60)
        print("Analysis Complete")
        print(f"Report saved as: {report_file}")
        print("=" * 60)
    else:
        print("Input error, please enter 1-7")
        valid = True