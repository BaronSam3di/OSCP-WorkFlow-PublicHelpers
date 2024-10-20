






## .zshrc alias to launch into a box : `box-OSCP`

#### first I run this script through an alias

```sh
#!/bin/bash
# Script to create a new CherryTree file for a new target with directory creation

# Get the IP or machine name as input
read -p "Enter the target IP or machine name: " TARGET

# Define the template path
TEMPLATE_PATH="$HOME/Documents/PentestCherryTreeTemplate.ctb"

# Create a new directory with the target IP and "-Box" suffix
TARGET_DIR="$HOME/notes/${TARGET}-Box"
mkdir -p "$TARGET_DIR"   # Create the directory if it doesn't exist

# Define the new file path inside the newly created directory
NEW_NOTE_PATH="$TARGET_DIR/$TARGET.ctb"

# Copy the template to the new CherryTree file
cp "$TEMPLATE_PATH" "$NEW_NOTE_PATH"

# Move into the target directory
cd "$TARGET_DIR"

# Open the new CherryTree note in the background
nohup cherrytree "$NEW_NOTE_PATH" &

# Run the Recon-Start.sh script with the target IP as an argument
/home/kali/Recon-Start.sh "$TARGET"
```

#### The contents of Recon-Start.sh

```sh
#!/bin/bash

# Check if IP address is provided as an argument
if [ -z "$1" ]; then
  echo "Usage: $0 <IP Address>"
  exit 1
fi

IP="$1"

# Step 1: Open the IP in Firefox
echo "=========================="
echo "[*] 4 pings of $IP to check its up"
echo "=========================="
ping -c 3 $IP 


# Step 1: Open the IP in Firefox
echo "=========================="
echo "[*] Opening $IP in Firefox"
echo "=========================="
firefox "http://$IP" &



# Step 3: Perform a curl request to check the server response
echo "================================="
echo "[*] Running curl request to $IP"
echo "================================="
curl -I http://$IP > curl_$IP.txt
cat curl_$IP.txt


# Step 2: Perform an initial nmap scan (common ports)
echo "==================================="
echo "[*] Running initial Nmap scan (top 1000 ports)"
echo "==================================="
nmap -oN initial_nmap_$IP.txt $IP



# Step : DNSENUM 100 thread
echo "==================================="
echo "[*] Running DNSenum"
echo "==================================="
dnsenum $IP --threads 100



# Step 4: Run a comprehensive nmap scan (all ports)
echo "===================================="
echo "[*] Running comprehensive Nmap scan (all open ports)"
echo "===================================="
nmap -p- -sC -sV -oA full_nmap_$IP.txt $IP --open


# Step : Deeper DNSENUM 100 thread
echo "==================================="
echo "[*] Running Deeper DNSenum"
echo "==================================="
dnsenum --enum --dnsserver 8.8.8.8 --threads 10 --scrap 50 --pages 10 --file /usr/share/wordlists/seclists/Discovery/DNS/shubs-subdomains.txt --recursion --whois --output results.xml $IP

# Step 5: Run GoBuster to enumerate directories
echo "===================================="
echo "[*] Running GoBuster to enumerate directories"
echo "===================================="
gobuster dir -u $IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -t 20 -o gobuster_$IP.txt

# Final output
echo "===================================="
echo "[*] Enumeration complete for $IP"
echo "===================================="

```



## "Term" hunter alis which lives in my .zshrc

```sh
xs() {                                                                                                                   
    # Check if an argument is provided                                                                                   
    if [ -z "$1" ]; then                                                                                                 
        echo "Error: Please provide a search term."                                                                      
        return 1                                                                                                         
    fi                                                                                                                   
                                                                                                                         
    # Define the path to your snippets file                 
    SNIPPETS_FILE="/home/kali/OSCP/OSCP-COURSE-Notes/OSCP-Obsidian-Vault/HackingSnippets-2024.md"
                                                            
    # Check if the snippets file exists                                                                                  
    if [ ! -f "$SNIPPETS_FILE" ]; then                                                                                   
        echo "Error: Snippets file not found at $SNIPPETS_FILE"                                                                                                                                                                                    
        return 1                                                                                                         
    fi                                                      
                                                                                                                         
    # Search for the term in the file and print results with eye-catch separator                                         
    grep --color=always -i "$1" "$SNIPPETS_FILE" | while IFS= read -r line; do
        echo "---------"                                                                                                 
        echo "$line"                                   
    done                                                                                                                 
                                                            
    # Check if grep found any matches                                                                                    
    if [ $? -ne 0 ]; then      
        echo "No results found for '$1'"                                                                                 
    fi
}                                                           
```
