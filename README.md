# CSC-842-Summer-2023-Cycle5

**802.11 Scanner**

After scanning the local wireless network for connected devices in Cycle 1, I decided to move laterally and make a tool that scans for surrounding Wi-Fi networks. This application will be working with 802.11 protocol and will scan the surroundings for available broadcasting wireless networks. It all has an option to scan hidden Wi-Fi networks. Another option available will allow finding connected client devices for the selected network. One last option would allow running a de-authentication attack on one or all the devices connected to the network.

**Three main ideas:**
1.	Running a wireless adapter in monitor mode allows one to scan, monitor, analyze, and control wireless traffic and devices.
2.	Wireless or Wi-Fi networks use 802.11 protocol. This protocol has management and data frames. Capturing and analyzing the frames allows us to identify and manipulate wireless traffic.
3.	De-authentication is a wireless attack that sends deauth frame to the client, which requires the client to reauthenticate on the network, which would allow an attacker to capture the authentication frames to crack the password.

**Limitations and future work**
This project was limited by using an AWUS036NEH Alfa card, which only uses the 2.4GHz band, while all my wireless networks are heavily utilizing the 5GHz band. As for future work, I would like to add a module that would capture the re-authentication traffic and attempt to crack the passwords.

**Running the program**
If you are planning to run the code, you need to use Kali, BackBox, or Parrot VMs. Otherwise, you will need to install the Airmon-ng packages. You also need to start with option 6 to enable monitor mode on your wireless network adapter. If your adapter doesn’t allow monitor mode, you would need to use an Alfa card. Happy scanning!
