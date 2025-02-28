# SOC Automation Project

### OS Used: 
- **Windows 10 Server**
- **Ubuntu VM Server** (Digital Ocean Cloud Based)
### Security Tools Used:
- **TheHive (Case Management)**
- **ElasticSearch**
- **Cassandra**
- **Wazuh(SIEM)**
- **Shuffle (Automation)

<h2>Part 1: Create a diagram of the project.</h2>
- **This diagram will make it easier to understand how the project will be created using many different apps.**

![SOC Automation Lab Diagram drawio](https://github.com/user-attachments/assets/a137c8a7-f5f0-4539-b4c3-f030a5474268)

<h2>Part 2: (Creating VM and Sign up with Digital Ocean)</h2>

Step 1: Sign up for Digital Ocean, and you should receive a free $200 trial.

Step 2: Create a Droplet (Configuration
Choose the default location of where you are located. 
![create droplet #1](https://github.com/user-attachments/assets/b3e6c7ef-1c31-42fc-94a5-1eb07c84f285)
Step 3: 
Choose Ubuntu with the latest version
![create droplet #2](https://github.com/user-attachments/assets/7a9b3679-a263-495b-bd0e-d45faddfb3f5)
Step 4: 
Choose the droplet with 8GB of memory and 160 GB of storage.
![droplet#3](https://github.com/user-attachments/assets/6b0054be-9400-4382-ae41-efabb9d7522e)

Step 5:
Now you would need to create a password.
![droplet #5](https://github.com/user-attachments/assets/4c16ea8d-d8dd-46a4-8214-6f7aa5083bf0)

Step 6:
Finally, name the droplet "thehive" and click "create droplet".
![thehive droplet](https://github.com/user-attachments/assets/0486f0cb-f48a-4643-a1c4-84874bde4a75)

Step 7:
The droplet for the hive has is successfully created.

Step 8:
Next, create another droplet with the same configurations repeated from steps 1 to 6 but renamed the droplet "Wazuh".
![wazuh droplet](https://github.com/user-attachments/assets/2e8e042c-cf4d-44e3-ac80-73a01c091af8)

Step 9:
After creating both droplets, go to one of the droplets and continue to "Networking" and scroll down and click on "Firewall".
![network firewall](https://github.com/user-attachments/assets/46f50f8b-490c-49a9-a987-b935cc784aca)

Step 10:
"Click on Create Firewall"
![firewall](https://github.com/user-attachments/assets/8cf469f6-9f7a-4876-ac45-66f59ce76220)

Step 11:
After TheHive and Wazuh droplet have been created, you must create a firewall rule and add your public IP address. This will prevent brute force attacks on TheWazuh and TheHive droplets as we will access the internet.
Insert your public IP address where I have it blurred, and configure the TCP and UDP rules shown within the image.
![Network Firewall Rules](https://github.com/user-attachments/assets/122ae8cf-804c-4558-84c4-f2a42d2b5b7b)

Step 12: 
You would need to do it for both VM instances in which in the screenshot "add the droplet" of the firewall that has been created to the other VM.
![image](https://github.com/user-attachments/assets/d09bed8b-29f3-4a88-9f42-1af170e81e49)

You should see this screenshot in which I have the Wazuh droplet already added so you would need to search for the "TheHive" droplet.
![image](https://github.com/user-attachments/assets/d0a47aaa-7c08-430c-96d0-b5d86643d824

<h2>Part 3: Windows installation</h2>
Step 0: The Windows 10 VM will be our sandbox in which we can release our Mimikatz exploit into our VM and able to receive logs/events. 
Recommend watching the YouTube video for Windows 10 installation on Virtual box: https://www.youtube.com/watch?v=CMGa6DsGIpc&pp=ygUed2luZG93cyAxMCB2aXJ0dWFsYm94IHR1dG9yaWFs

- Before starting this project I already had a Windows 10 VM installed on VMWare Workstation.
![image](https://github.com/user-attachments/assets/20def673-0168-45cf-b964-d9f217d87dc2)

<h2>Part 4: Install Sysmon & Mimikatz</h2>
Step 1:  Install sysmon and extract it in the downloads folder.
Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
Sysmon Config: https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml


Step 2: After downloading Sysmon go into PowerShell and the directory of the extracted powershell and execute the command within the screenshot.
![sysmon 2](https://github.com/user-attachments/assets/f70d1a40-e20a-4769-b939-d99c3f2d3d72)

Step 3: Execute the command again with the screenshot.
![sysmon #7](https://github.com/user-attachments/assets/9e6553d9-2f08-4a25-aa3f-4e9945cde3d6)

Step 4: You must downnload Mimikatz trunk
Download: https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20220919

Step 5: Make sure the file is extracted.
![Mimikatz](https://github.com/user-attachments/assets/652d3ba9-582c-4e31-8c05-2adba31e5ece)


<h2>Part 5: (Wazuh Installation) </h2> 

Step 1: Connect to the Wazuh droplet ubuntu virtual machine server. Within project, I used "Putty" to SSH into the virtual machine. - https://www.putty.org/


Step 2: After able to SSH into Wazuh and login with root/password, run the following command to get latest update packages: apt-get update && apt upgrade

Step 3: The latest package should be installed and now we can head over and install the latest version of Wazuh. (Install Here - https://documentation.wazuh.com/current/quickstart.html)
![wazuh website](https://github.com/user-attachments/assets/cfa74349-251d-4435-abd5-f902965c6235)

Step 4: Installation of Wazuh should be started similar to the screenshot below
![wazuh install curl](https://github.com/user-attachments/assets/bb09b64b-add7-4620-9bb0-11a4b8e3703a)


Step 5: You should be receiving credentials of "username" and "password" in which this will be how you sign into Wazuh.  
![wazuh installation complete](https://github.com/user-attachments/assets/48bcc98f-9966-4738-886b-03909596b643)


Step 6: Head to your Wazuh dashboard by entering: https://wazuh_droplet_ip_address
![image](https://github.com/user-attachments/assets/9b9b666a-d022-454e-a8c5-0b5e43e9461b)

Step 7: Select Windows MSI 64 bits and make sure to enter the public IP address of your Wazuh droplet. Also give a name to the agent to whatever you like.
![image](https://github.com/user-attachments/assets/af9a9f65-ac52-4c64-8f43-09391068f4b2)

Step 9: Copy the command and execute the command with the Powershell. Make sure to run the Powershell administrator as well.
![image](https://github.com/user-attachments/assets/621baee3-4daf-4153-8e9f-44b0a16d9e58)

Step 10: Successfully after executing the commands this should be the results after.
![image](https://github.com/user-attachments/assets/8147dcfd-fbd3-477f-82b3-77507d6227dc)

Step 11: This screenshot shows that the Wazuh is installed within the Programs section.
![Wazuh Agent installation](https://github.com/user-attachments/assets/4b02ba1e-dd5b-4781-915f-15e7c3eab528)

Step 12: Login into Wazuh with the credentials from Step 5 and click on "Active".
![wazuh overview](https://github.com/user-attachments/assets/adc60f76-fbb8-4cf9-9a6a-b686446aa551)

You should be in the endpoint tab and able to see the Wazuh agent that you installed.
![wazuh endpoints #2](https://github.com/user-attachments/assets/dbf93909-d0cf-429f-8e46-28117962eb34)

Part 5: (Windows Telemetry & Firewall Exclusions)
Step 1: Go to file directory path - C:\Program Files (x86)\ossec-agent and open the file ossec.conf file.
Create a backup file of the ossec.conf file. Make sure the ossec.conf file is exactly the same in the screenshot.
![windows10telemetry](https://github.com/user-attachments/assets/65171214-8e4f-4c67-ba72-ea0497e69192)

Step 2: Add the folder to he firewall exclusions where mimikatz is extracted which is the Downloads folder for me.
![exclusions](https://github.com/user-attachments/assets/841c0e71-4f20-41bf-ba91-b33d20d44e4b)

<h2>Part 6: (Wazuh Configuration)</h2>

Step 1: Create a copy of the ossec.conf file
<p>Run the following command:</p>
<pre><code>cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak</code></pre>
<img src="https://github.com/user-attachments/assets/45b81529-a6bf-4aaf-af91-e15f8ded747e" alt="OSSEC Backup Command" width="600">

Step 2: Configure the ossec.conf file within the Wazuh droplet</h2>
<p>Edit the configuration file:</p>
<pre><code>nano /var/ossec/etc/ossec.conf</code></pre>
<p>Make sure to save it by pressing <strong>CTRL+X</strong>, then <strong>Y</strong>, and <strong>Enter</strong>.</p>
<img src="https://github.com/user-attachments/assets/6e19322c-8c43-43be-b7b8-65aaa9a46537" alt="OSSEC Config" width="600">

Step 3: Restart Wazuh Service
<p>Restart the service with:</p>
<pre><code>systemctl restart wazuh-manager</code></pre>
<img src="https://github.com/user-attachments/assets/a6d1ad91-c508-46cf-87d5-c7fb948115b9" alt="Wazuh Restart" width="600">

Step 4: Configure Filebeat
<p>Modify the Filebeat configuration as needed.</p>
<img src="https://github.com/user-attachments/assets/cf7a6841-8ffb-438f-a505-f5091dbfd1e3" alt="Filebeat Config" width="600">

Step 5: Restart Filebeat
<p>Restart the Filebeat service:</p>
<pre><code>systemctl restart filebeat</code></pre>
<img src="https://github.com/user-attachments/assets/53b7134d-7f07-4599-a2e1-68c4fcd509e5" alt="Systemctl Restart" width="600">

Step 7: Go to the index tab
![image](https://github.com/user-attachments/assets/fcf3bc22-6520-41bc-a86d-83b4025a86d1)

Step 8: Create an index
![wazuh_archives](https://github.com/user-attachments/assets/d7435a3a-dd1c-411e-8348-93d07e5d4558)

Step 9: Configure index settings similar to screenshot and click create index.
![index pattern timestamp](https://github.com/user-attachments/assets/b177170b-3262-4fe0-9eed-9ae3cab4f6bf)


Step 10: You must activate the Wazuh agent, so scroll down to settings. 
![settings wazuh](https://github.com/user-attachments/assets/87792b38-cd00-4570-a3ff-ab9fac970a1d)

<h2>Part 7: TheHive Installation</h2>
Step 1 - Install the [Hive Installation]:(https://github.com/divyank50/SOC-Automation-Lab/blob/main/Hive_Installation)

Step 2: You must install Java, Cassandra, elasticsearch and TheHive
- Java
![Screenshot_2025-02-16_at_3 07 18_PM](https://github.com/user-attachments/assets/5a9be7c3-e64f-42c9-9d58-6d4a84f9fe5e)
- Cassendra
![Screenshot_2025-02-16_at_3 07 29_PM](https://github.com/user-attachments/assets/fd47cd9a-5ee3-43bb-a34b-88b0428d1e30)
- Elasticsearch
![Screenshot_2025-02-16_at_3 07 44_PM](https://github.com/user-attachments/assets/c93a6b44-5239-4b4e-aded-92e2cb769d08)
- TheHive
![Screenshot_2025-02-16_at_3 08 00_PM](https://github.com/user-attachments/assets/6657587a-b995-49c5-a984-b0bae403aaa8)


Step 3: Configure some changes within /etc/cassendra/cassendra.yaml
<pre><code>nano /etc/cassendra/cassendra.yaml</pre></code>
![listen_address](https://github.com/user-attachments/assets/b28d6236-337d-4041-87f9-dc54efa3cb8e)
![rpc_address](https://github.com/user-attachments/assets/5f552a8e-5b8f-4b90-ad8b-41a779c090b3)
![seeds](https://github.com/user-attachments/assets/3e5a2cc5-f96e-4a6a-a7a9-bd77ab35c01d)

Step 4: Stop Cassendra and remove the old files
<pre><code>systemctl stop cassendra.service</pre></code>
<pre><code>rm -rf /var/lib/cassendra/</pre></code>
![stop cassdandra](https://github.com/user-attachments/assets/f0606f98-b229-40de-b6ae-fe991c8f6c74)

Step 5: Start up Cassendra
<pre>systemctl start cassendra.service</pre>

Step 6: Now we need to make changes within the elasticsearch.yml file
<pre><code> nano /etc/elasticsearch/elasticsearch.yml </code></pre>
![elasticsearch yml](https://github.com/user-attachments/assets/aa4bc03e-b7a5-42ff-ad8b-e3d262c9cb9d)
- Provide public IP address of the droplet
- Uncomment the "HTTP .port": 9200
- Only use the running 1 node
![elasticsearch yml #2](https://github.com/user-attachments/assets/20519645-a25e-4803-b71a-9c0cc9a8ef34)

Step 7: Execute an Elasticsearch restart
<pre><code> systemctl restart elasticsearch</pre></code> 

Step 8: Configure the filebeat.yml file
<pre><code> nano var/ossec/logs/archives </code></pre>
![filebeat](https://github.com/user-attachments/assets/908a0f17-70cb-4dae-b4ff-e4f091ac54f7)
And make sure to restart filebeat
<pre><code>systemctl restart filebeat</code></pre>
![systemctl restart](https://github.com/user-attachments/assets/ec395b9d-1143-4842-a940-89fc6630e10c)

Step 9: Change the folder access of the hive from root to "thehive" user can access "chown -R thehive:thehive /opt/thp".
![thehive chown](https://github.com/user-attachments/assets/860fc0a8-9f62-459c-bb22-53f60f7dea2b)

Step 10: Now we need to configure the thehive application.conf file
<pre><code>nano /etc/thehive/application.conf</code></pre>
![applicationconf ](https://github.com/user-attachments/assets/eca5ce65-3fa3-4baa-8e37-626aad38121f)
Make sure to add your public IP address like how it is below.
![applicationconf #2](https://github.com/user-attachments/assets/90cba8bd-54f3-45c8-a31a-fe7330aa3d88)

<h2>Part 8: SIEM Events & Alerts within Wazuh Configuration</h2>
Step 1: Lets head to the Windows VM and head to Wazuh.
Open PowerShell and head to the directory of where Mimikatz folder is located. The Mimikatz.exe file is inside x64 folder.
Execute within the powershell command
<pre><code>./Mimikatz/</code></pre>

Step 2: After executing the Mimikatz we should see the event from the archives index from Part 5 step 8 that we created.
![mimkatz ](https://github.com/user-attachments/assets/0ce3b3d6-0acb-4f4f-bb2d-59963258a59e)

Events of Mimikatz
![mimikatz wazuh](https://github.com/user-attachments/assets/ec7296ae-83b5-44d0-adee-fcf75c72f952)

Step 3: Now we are going to create an alert for this malware.
![local_rules_mimikatz](https://github.com/user-attachments/assets/c349d503-0b14-4d63-a28e-0f6bfdca1e1e)

Step 4: After successfully creating the alerts within local_rules a alert should pop up within Threat managment tab.
Screenshot: 

<h2>Part 9: Automation Alerts</h2>


