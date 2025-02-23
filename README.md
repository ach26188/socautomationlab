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

### Part 1: Create a diagram of the project.
- **This diagram will make it easier to understand how the project will be created using many different apps.**

![SOC Automation Lab Diagram drawio](https://github.com/user-attachments/assets/a137c8a7-f5f0-4539-b4c3-f030a5474268)

### Part 2: (Creating VM and Sign up with Digital Ocean)

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

### Part 3: Windows installation
Intro: The Windows 10 VM will be our sandbox in which we can release our Mimikatz exploit into our VM and able to receive logs/events. 
Recommend watching the YouTube video for Windows 10 installation on Virtual box: https://www.youtube.com/watch?v=CMGa6DsGIpc&pp=ygUed2luZG93cyAxMCB2aXJ0dWFsYm94IHR1dG9yaWFs
Step 0: Before starting this project I already had a Windows 10 VM installed on VMWare Workstation.
![image](https://github.com/user-attachments/assets/20def673-0168-45cf-b964-d9f217d87dc2)


### Part 4: (Wazuh Installation) 

Step 1: Connect to the Wazuh droplet ubuntu virtual machine server. Within project, I used "Putty" to SSH into the virtual machine. - https://www.putty.org/


Step 2: After able to SSH into Wazuh and login with root/password, run the following command to get latest update packages: apt-get update && apt upgrade

Step 3: The latest package should be installed and now we can head over and install the latest version of Wazuh. (Install Here - https://documentation.wazuh.com/current/quickstart.html)
![wazuh website](https://github.com/user-attachments/assets/cfa74349-251d-4435-abd5-f902965c6235)

Step 4: Installation of Wazuh should be installed successfully according to the screenshot below.
![wazuh install curl](https://github.com/user-attachments/assets/bb09b64b-add7-4620-9bb0-11a4b8e3703a)


Step 5: You should be receiving credentials of "username" and "password" in which this will be how you sign into Wazuh.  
![wazuh installation complete](https://github.com/user-attachments/assets/34869918-0e45-49e7-9262-da2818642418)

Step 6: 


