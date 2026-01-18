# splunk-ssh-bruteforce-detection
SSH brute‑force detection in Splunk using Linux sshd logs. The lab creates a simple SPL rule that reads linux_secure auth logs, separates failed and successful logins, and flags any IP that has several failed SSH password attempts followed by a successful login — a strong sign of a brute‑force attack.
