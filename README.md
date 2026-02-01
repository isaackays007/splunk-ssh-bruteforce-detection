# Splunk SSH Brute-Force Detection

SSH brute-force detection in Splunk using Linux sshd logs. This lab creates a simple SPL rule that reads `linux_secure` auth logs, separates failed and successful logins, and flags any IP that has several failed SSH password attempts followed by a successful login — a strong sign of a brute-force attack.

## 1. Objective

The goal of this lab is to detect successful SSH brute-force attacks against a Linux host by analyzing `linux_secure` sshd logs in Splunk. The detection identifies source IPs that generate multiple failed SSH password attempts followed by at least one successful login, which is a typical brute-force pattern.

## 2. Data and exploration

I first validated that Linux authentication logs were being ingested into Splunk as `linux_secure` events from the sshd process. By searching for `Failed password` and `Accepted password` messages, I could see individual SSH login failures and successes from my attacker IP against the test user.

```spl
index=main sourcetype=linux_secure process=sshd ("Failed password for" OR "Accepted password for")
```
![SSH brute-force events](screenshots/Screenshot_2026-01-19_10-51-17.png)

## 3. Detection logic (SPL)

To detect brute-force behavior with a final success, I used the following SPL:

```spl
index=main sourcetype=linux_secure process=sshd ("Failed password for" OR "Accepted password for")
| rex field=_raw "(?<result>Accepted|Failed) password for (invalid user )?(?<user>\S+) from (?<src>\d+\.\d+\.\d+\.\d+)"
| eval status=if(result="Failed","failed","success")
| stats count AS total_events
        count(eval(status="failed"))  AS failed_count
        count(eval(status="success")) AS success_count
        min(_time) AS first_time
        max(_time) AS last_time
  BY src
| where failed_count>=3 AND success_count>=1

This search parses each sshd event, classifies it as a failed or successful login, then aggregates by source IP. It flags IPs that have at least three failed attempts and at least one success in the time window, indicating a likely brute-force attack that eventually succeeded.

![Detection statistics](screenshots/Screenshot_2026-01-19_10-55-25.png)

## 4. Results and observations
When I ran the attack from the Kali VM, this SPL correctly identified the attacker IP as having multiple failed SSH password attempts followed by a successful login. This demonstrates how Splunk can be used to detect successful SSH brute-force activity using Linux authentication logs and simple SPL.
