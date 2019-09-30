# Dynamic_Honeypot
Dynamic honeypot system written in python 

This is still very much a work in progress, currently I am focussing on refactoring the entire codebase to be of a professional 
standard before I work to add and refine the functionality. This is visible with the change from the bespoke get_os_and_ip.py 
to the more generic create_honeypots.py

My current goal for this project is to complete this refactor. This may or may not be done before university ends for the school 
year.

After university has ended I plan to alter this project to be signficantly more generic, so that it can create configs for a
variety of honeypot systems. This is a result of the rather poor results I feel HoneyD has produced, and the vulnerabilities it
has.

As it stands now the honeypot generator config is close to being this generic, and the read_log.py file will need to be changed
to accept .pcap files. 
