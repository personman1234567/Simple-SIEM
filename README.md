# Simple-SIEM
In this project, I give myself a hands on introduction to SIEM using Microsoft Sentinel on Azure.

## Table of Contents

- [Overview](#overview)
- [Setting Up the Vulnerable VM](#setting-up-the-vulnerable-vm)
- [Configuring Microsoft Sentinel](#configuring-microsoft-sentinel)
- [Data Integration](#data-integration)
- [Monitoring & Alerts](#monitoring--alerts)
- [Incident Example](#incident-example)
- [Next Steps](#next-steps)

## Overview

In this project, I explored the fundamentals of SIEM by:
- Deploying a vulnerable VM.
- Configuring Microsoft Sentinel with a Log Analytics Workspace.
- Integrating the VM’s event logs into Sentinel.
- Creating alert rules to trigger incidents based on security events.

## Setting Up the Vulnerable VM

I started by setting up a virtual machine—nothing fancy, since it was meant to be vulnerable. I chose a Windows 11 instance, left port 3389 (RDP) open, and used a very basic password to make it susceptible to brute force attacks.
![image](https://github.com/user-attachments/assets/0fd792ec-c139-459e-9234-5cd203eeb1b7)

## Configuring Microsoft Sentinel

While the VM was deploying, I began setting up Microsoft Sentinel by creating a Log Analytics Workspace. I used the same resource group I had created for the VM. Once I added Microsoft Sentinel to the workspace, I was greeted with its main dashboard, which initially featured several empty charts. (The screenshot shows one incident, captured after I ran my experiment.)
![image](https://github.com/user-attachments/assets/40b6820e-0302-4ea8-b6fa-d34f3037703c)

## Data Integration

Next, I needed to integrate the VM with Microsoft Sentinel by setting up its Event Logs to be forwarded to the Log Analytics Workspace, and from there into Sentinel. To do this, I navigated to the Data Connector section in Sentinel, accessed the content hub, located the Windows Security Events connector, and installed it.
![image](https://github.com/user-attachments/assets/b04f2c34-b486-483e-9ef8-591c2f05e365)

After installing the connector, I configured Windows Security Events via the Azure Monitor Agent (AMA) by creating a collection rule. This rule pulled data and security logs from my VM, set to capture all security events. Once everything was in place, I stepped away and let the system run. All security events were logged and visible in Sentinel.
![image](https://github.com/user-attachments/assets/6b93bb60-96b9-411d-b228-ba05d10086e6)

## Monitoring & Alerts

A few hours later, I returned to my computer and opened the Logs tab in Sentinel. To confirm that security events were being recorded, I started with a simple query on the SecurityEvent table. It didn't take long to notice that hundreds of events had already been logged, many of them indicating brute force attacks.
![image](https://github.com/user-attachments/assets/94ecf9d9-cbf0-40dd-9793-b3cd5ad55302)

## Incident Example

The key security event I wanted to flag as an incident was a successful login attempt, because that indicates someone gained access to the machine. To focus on those events, I ran a query that filtered for entries where the login was successful and the Account field didn’t contain “system”, because I wanted to filter out internal processes.
![image](https://github.com/user-attachments/assets/733dbf96-4121-442f-8253-16e734a38108)

With that query I wanted to create a new sentinel rule, so that any event that satisfies that query will mark the event as an incident alert, titled "Successful LOCAL Login Attempts". It is set to update every 5 minutes.
![image](https://github.com/user-attachments/assets/eb061d8a-22ce-4f5a-8bd9-3469e02bbe1d)

Despite receiving numerous brute force attack attempts, none of them managed to guess the password "Password1234." So, I decided to connect using Remote Desktop Connection from my own computer—and sure enough, I successfully logged into the VM!
![image](https://github.com/user-attachments/assets/0c609311-3e6e-473d-9fd9-df7b1a10a889)

As shown in a previous screenshot, my login triggered an incident based on the rule I had set up. This confirms that the SIEM is successfully monitoring and alerting based on events from the VM. Now that I've proven this concept, I'm excited to experiment with additional event types to trigger different alerts!
![image](https://github.com/user-attachments/assets/c7ad3905-e9f9-46f0-b9df-d98f7154ddfd)

## Next Steps

Now that I had an alert configured to trigger an incident whenever an attacker successfully gains access to my machine, I wanted to take it a step further. I realized it would be incredibly valuable to be notified as soon as an attacker begins their assault. Since brute force attacks are so common, I decided to create an alert that would detect and notify me when an attacker is actively attempting a brute force attack.

The query shown in the screenshot was designed to detect brute force attacks. My approach was based on the assumption that 10 failed login attempts from a single source IP within a 10-minute window is a strong indicator of an attack. To implement this, I set a threshold variable at 10, meaning any IP exceeding this threshold within the specified timeframe would be flagged as a potential brute force attempt.

The query is structured to first filter events based on the event ID—specifically, 4625, which corresponds to failed login attempts. It then counts the number of failed attempts per unique source IP. If the count meets or exceeds the defined threshold, the IP is included in the query results, signaling possible malicious activity.

![image](https://github.com/user-attachments/assets/9514d447-5f39-41f9-9b0b-834194499f19)

Initially, I designed the query to detect brute force attacks by identifying source IPs with 10 or more failed login attempts within a 10-minute window. However, I later realized that when creating a Sentinel rule, the platform already provides options to define the time window and query execution schedule. This meant my initial query was more complex than necessary, so I simplified it to this:

```
let threshold = 10;
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress)
| summarize FailedAttempts = count() by IpAddress
| where FailedAttempts >= threshold
```
Additionally, I configured entity mapping for the IpAddress variable. This is so that within each generated alert message, I can see all the IP addresses flagged as attackers during the specified time window. By mapping the entity, Sentinel automatically associates the flagged IPs with security incidents, making it easier to track and investigate malicious activity.
![image](https://github.com/user-attachments/assets/aae0b4b7-1c85-45d4-925b-cf88ace962ae)

With that, my new rule was complete, and it was time to sit back and monitor the incidents generated over the next period.
![image](https://github.com/user-attachments/assets/9df6bdb0-6a68-448b-aaca-ba52a2f5d26f)
