#!/bin/bash

# Function to display ASCII art
display_ascii_art() {
    cat << "EOF"
                                                   /~~\
     ____                                         /'o  |
   .~  | `\             ,-~~~\~-_               ,'  _/'|
   `\_/   /'\         /'`\    \  ~,             |     .'
       `,/'  |      ,'_   |   |   |`\          ,'~~\  |
       |   /`:     |  `\ /~~~~\ /   |        ,'    `.'
        | /'  |     |   ,'      `\  /`|      /'\    /  1.2
        `|   / \_ _/ `\ |         |'   `----\   |  /'
         `./'  | ~ |   ,'         |    |     |  |/'
          `\   |   /  ,'           `\ /      |/~'
            `\/_ /~ _/               `~------'
               ~~~~
 ____                   __        __                     _   ____
|  _ \ ___  ___ ___  _ _\ \      / /__  _ __ _ __ ___   / | |___ \
| |_) / _ \/ __/ _ \| '_ \ \ /\ / / _ \| '__| '_ ` _ \  | |   __) |
|  _ <  __/ (_| (_) | | | \ V  V / (_) | |  | | | | | | | |_ / __/
|_| \_\___|\___\___/|_| |_|\_/\_/ \___/|_|  |_| |_| |_| |_(_)_____|
--------------------------------------------------------------------
      It's a little itty bitty worm that does recon for you :)
               Made with <3 by coffeeaddict
              ------------------------------
EOF
}

# Function to display a message with delay
display_message_with_delay() {
    message="$1"
    delay="$2"
    echo "$message"
    sleep "$delay"
}

# Function to prompt for recon output directory
prompt_for_recon_output() {
    read -p 'Recon output directory to create: ' DIR
    mkdir -p "$DIR" && echo "Done!!!" || { echo "Error: Unable to create directory"; exit 1; }
}
sleep 3

# Main script execution
clear
sleep 1

display_ascii_art

display_message_with_delay "Running....." 1
display_message_with_delay "Still running......" 2
display_message_with_delay "Tip: Please make sure you have all tools from the install.sh file" 1

prompt_for_recon_output

clear
sleep 2
DOMAIN=$1
OUTPUT=$1
# Subdomain enumeration script with advanced features

# Function to print the ASCII art banner
cat << "EOF"

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::      $$$$$$\            $$\             $$$$$$$$\                                        ::
::     $$  __$$\           $$ |            $$  _____|                                       ::
::     $$ /  \__|$$\   $$\ $$$$$$$\        $$ |      $$$$$$$\  $$\   $$\ $$$$$$\$$$$\       ::
::     \$$$$$$\  $$ |  $$ |$$  __$$\       $$$$$\    $$  __$$\ $$ |  $$ |$$  _$$  _$$\      ::
::      \____$$\ $$ |  $$ |$$ |  $$ |      $$  __|   $$ |  $$ |$$ |  $$ |$$ / $$ / $$ |     ::
::     $$\   $$ |$$ |  $$ |$$ |  $$ |      $$ |      $$ |  $$ |$$ |  $$ |$$ | $$ | $$ |     ::
::     \$$$$$$  |\$$$$$$  |$$$$$$$  |      $$$$$$$$\ $$ |  $$ |\$$$$$$  |$$ | $$ | $$ |     ::
::      \______/  \______/ \_______/       \________|\__|  \__| \______/ \__| \__| \__|     ::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

EOF


read -p 'HOST DOMAIN: ' DOMAIN
read -p 'OUTPUT FILE: ' OUTPUT
wget https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -O $DIR/resolvers.txt

# Function to perform subdomain enumeration

    echo "Running subdomain enumeration..."
    subfinder -d $DOMAIN -o $DIR/$OUTPUT
    assetfinder --subs-only $DOMAIN | tee -a $DIR/$OUTPUT
    echo "Subdomain enumeration completed. Running httpx..."

# Function to perform httpx scanning
    {
cat "$DIR/$OUTPUT" | httpx -silent -o "$DIR/httpx.txt"
cat "$DIR/$OUTPUT" | httpx -title -status-code -tech-detect -follow-redirects -silent -o "$DIR/status.txt"
    echo "httpx completed. Now testing for subdomain takeover..."
}
       {

    subjack -w $DIR/$OUTPUT -v | tee -a takeovers.txt

    echo "Subdomain enumeration finished."
}

echo "other code running"
# Bruteforce permutations (e.g., api-dev, vault-pro
cat $DIR/$OUTPUT | massdns -r $DIR/resolvers.txt -t A -o J -w $DIR/massdns-out.json  

# Merge and deduplicate results from multiple tools  
amass enum -passive -d $DOMAIN -o $DIR/amass.txt   
  

# Resolve live hosts with HTTPX  
cat $DIR/amass.txt | httpx -silent -ports 80,443,8080,8443 -status-code -title -tech-detect -o $DIR/live_hosts.txt  
# Function to check for subdomain takeover

sleep 3 
echo "done"



clear



sleep 1
# Function to display ASCII art
display_ascii_art() {
    cat << "EOF"
////////////////////////////////////////////////////////
// ____            _                                  //
//|  _ \ ___  _ __| |_    ___ _ __  _   _ _ __ ___    //
//| |_) / _ \| '__| __|  / _ \ '_ \| | | | '_ ` _ \   //
//|  __/ (_) | |  | |_  |  __/ | | | |_| | | | | | |  //
//|_|   \___/|_|   \__|  \___|_| |_|\__,_|_| |_| |_|  //
////////////////////////////////////////////////////////
EOF
}

# Function to perform naabu mass port scan
run_naabu_scan() {
    echo "Depending on your target, this may take a while."
    echo "It's worth it, so just sit back and get a coffee :)"

    sleep 3
    echo "Running naabu mass port scan...."
    cat $DIR/$OUTPUT | naabu | tee -a ports.txt || { echo "Error: Naabu scan failed"; exit 1; }
    echo "Scan completed!"
}

# Function to filter FTP and SSH ports
filter_ports() {
    echo "Filtering FTP and SSH ports..."
    sleep 2
    grep -w 21 ports.txt > ftp.txt
    grep -w 22 ports.txt > ssh.txt
    cat ports.txt | grep -v -e "443" -e "80" > otherports.txt

    echo "Done!"
   cat ftp.txt
   cat ssh.txt
read -p 'look it over, press enter when done'
}


# Function to provide tips
display_tips() {
    echo "TIP: Try testing for anonymous login on FTP servers"
sleep 3
echo "running nuclei testing on ports/subs...."
sleep 1
cat otherports.txt | nuclei | tee -a nucleiportresults.txt

echo "running crawl of file and js scrape"
echo "endpoint shit..."
sleep 2
cd $DIR
# Extract URLs from Wayback Machine + Common Crawl
waybackurls $DOMAIN | gau | grep "\.js$" | anew urls.txt

# Hunt for secrets in GitHub
gitgraber -k keywords.txt  $DOMAIN -d



cat urls.txt | grep ".js" | httpx -sr -s js | tee -a js.txt
cd
cat workscript/$DIR/js.txt | nuclei -t  nuclei-templates/http/misconfiguration | tee -a workscript/$DIR/Nmisconfig.txt
cat workscript/$DIR/js.txt | nuclei -t nuclei-templates/http/exposures | tee -a  workscript/$DIR/Nexposures.txt
cd
cd workscript 
cd $DIR
mv $OUTPUT -f /home/coffeeaddict/workscript/urlscan/
cd
cd /home/coffeeaddict/workscript/urlscan
./url.sh

read -p 'done!!!'
}

# Main script execution
clear
display_ascii_art
sleep 2

run_naabu_scan

echo "Grepping FTP and SSH ports..."
filter_ports

display_tips

clear
