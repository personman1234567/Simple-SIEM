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
- [Threat Intelligence](#threat-intelligence)

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

I returned the next day to the Sentinel incidents tab and found 117 incidents! While everything was working as expected, with each incident clearly displaying the flagged IP addresses, the sheer volume was overwhelming and could drown out other important alerts that occurred overnight. Ideally, Sentinel should generate a single alert for each attacking IP address, rather than creating a new alert every 10 minutes for the same IP. Once an IP is flagged, the process should quarantine that issue until I can investigate further. After some research, I discovered that it's possible to automate this workflow using playbooks.
![image](https://github.com/user-attachments/assets/e97b46e1-4317-45af-a40d-c6a874dbae3e)

Playbooks is a new concept to me, so for automation I am going to start with something simple. I want to create an automation that will notify my email whenever a successful login occurs, which is an event that I already have set up to flag as an incident. So I first created this Logic App called NotifyLogin
![image](https://github.com/user-attachments/assets/4444eede-baab-484f-9403-b601ffd9b741)

In the Logic App Designer, this is where I built up the set of tasks that are triggered by certain events. What I have here is very simple. I set it up to trigger on alerts from the first rule I created, and upon that alert, this will proceed to create an email in a template that I created. For some reason, gmail was not liking the way I had it linked up, so I ended up having to go into my gmail account and create an app password, in order for this automated email to be sent over SMTP.
![image](https://github.com/user-attachments/assets/2cf6a891-f5e0-4d94-894f-b0a8c379b621)

Now that the playbook was set up, I navigated to Microsoft Sentinel, accessed the Automation tab, and created an automation rule. I linked the playbook I had created and configured it to trigger on alerts generated by that specific rule. With that, the setup was complete!

To test it, I connected to the machine via RDP again, and shortly after, I received an email notification confirming a successful login. However, as shown in the screenshot, most of the dynamic content parameters except for the timestamp were blank. This indicates that some of the dynamic fields were not set up correctly. Now that I understand the automation process, my next goal is to refine this setup and get those parameters working and, for my next experiment, to implement automatic quarantine/blocking for these brute force attackers.
![image](https://github.com/user-attachments/assets/4245eac7-ef47-42dd-aa3b-9102e232cf77)

NOTE: I have a limited number of free credits for Azure, which restricts what I can do at the moment. I plan to use my remaining credits on another project I’ve been wanting to try. If I have any credits left after that, I will return to this project and work on automating the quarantine and blocking of malicious IP addresses attempting to brute-force my machine.

## Threat Intelligence

For this part of the project, I am going to utilize MISP (an open source threat intelligence platform), and I am going to set it up to automatically push threat indicators over to Microsoft Sentinel.


Setting Up MISP was fairly straight forward:

1. I started by creating a new **Ubuntu VM** in Azure and connected to it using **SSH** via the **Azure CLI**.  

2. Once I had access, I installed **Docker** on the machine by following the official documentation:  
   [Docker Engine Installation for Ubuntu](https://docs.docker.com/engine/install/ubuntu/).  

3. With Docker set up, I proceeded to install **MISP** using their official **Docker image**. I followed the steps outlined in their repository:  
   [MISP Docker Installation](https://github.com/MISP/misp-docker), and after going through the setup, I successfully got it running.  

4. In order to access the MISP web interface, I had to adjust the **network settings** of my VM by opening **port 443 (HTTPS)**.  

5. Once that was done, I could access MISP from my own computer by navigating to the URL I configured, where I was greeted with the login screen, confirming that everything was set up correctly!

![image](https://github.com/user-attachments/assets/b8a721c4-585a-4366-a068-4c1cbd369ab6)


### Importing Threat Feeds into MISP

On the MISP web interface, threat indicators are sourced from Feeds. The MISP website provides a JSON file containing multiple preconfigured feeds that can be imported into a MISP instance:  
[Feed Metadata JSON](https://github.com/MISP/MISP/blob/2.4/app/files/feed-metadata/defaults.json).  

I simply copied the contents of this JSON file and pasted it into the Import Feeds section of the MISP web interface. After clicking Add, MISP successfully imported 83 new feeds, making them available for use.  

![image](https://github.com/user-attachments/assets/fc640af8-7d9b-4ec2-ae89-ca70ca43a833)
![image](https://github.com/user-attachments/assets/2baccd54-8b76-41c4-9d66-a2aa55b47e12)

While the feed data was being stored, I decided I'd use the time to integrate MISP with Microsoft Sentinel by configuring the MISP2Sentinel data connector. This will also require setting up API integration between the two platforms to allow data to transfer.
![image](https://github.com/user-attachments/assets/4fd94860-7890-49a9-b325-9c031afe4f16)

Created a Key Vault and now a Secret in that key vault, and I am putting the MISP Auth key from my MISP instance as the value of this secret
![image](https://github.com/user-attachments/assets/8801579c-31a6-4794-b31a-e80594a152ef)

I also created a secret for some of the other information in my app registration that my function app (something I am about to create) will need to use as variables. The app registration I created has important info like the Application (client) ID and the Directory (Tenant) ID.
![image](https://github.com/user-attachments/assets/7552b169-ae26-49d4-b165-136f39e00eae)

I then created a function app using Python 3.11 to run a script that I will later set up
![image](https://github.com/user-attachments/assets/514a84cd-b9f8-4b4b-9918-c689b45412ff)

In order for my function app to be able to use these secrets, I had to give it the proper permissions, so in my Key Vault, I went into Access Control (IAM) and added the role assignment "Key Vault Secrets User" to my Function App, allowing it to read these secrets from the key vault.
![image](https://github.com/user-attachments/assets/890be7bf-5b5b-4edc-bb5f-74c3e5adff66)

I then had to link up the variables that my function app will use, to the secrets that I set up in the key vault. So I had to go to the environment variables tab, and then individually configure each of the key vault references as variables that the function app will use. The green checkmark indicated that they were properly linked up to the key vault!
![image](https://github.com/user-attachments/assets/ba9efade-b09c-468e-9f4f-e343b27daf23)

I downloaded the misp2sentinel github project and opened it in VS Code. I configured config.py to pull all of the credentials and settings from the key vault and environmental variables I set up instead of hardcoding them. Assuming it all was done correctly, this setup should allow the Azure Function to securly connect to MISP, fetch threat intelligence, and send it to Sentinel. All without exposing any sensitive credentials in the code.
![image](https://github.com/user-attachments/assets/f29b5505-b532-46f2-81e3-c0fdf5bfa4e6)
