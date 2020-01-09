#!/bin/bash
echo -e "ScanCannon v1.0\n"

#Help Text:
function helptext() {
	echo -e "\nScanCannon: a program to enumerate and parse a large range of public networks, primarily for determining potential attack vectors"
	echo "usage: scancannon.sh [file . . .]"
}

#Make sure a non-empty file is supplied as an argument:
if [ "$#" -ne 1 ]; then
	echo "ERROR: Invalid argument(s)."
	helptext >&2
	exit 1
elif [ ! -s "$1" ]; then
	echo "ERROR: CIDR file is empty or does not exist"
	helptext >&2
	exit 1
fi

#Check for root:
if [ "$(id -u)" != "0" ]; then
	echo "ERROR: This script must be run as root"
	helptext >&2
	exit 1
fi

#Check if MacOS
if [ "$(uname)" = "Darwin" ]; then
	MACOS=1
else
	MACOS=0
fi

#Alert for existing Results files
if [ -s ./results ]; then
	read -p "Results folder exists. New results will be combined with existing. Re-scanning previous subnets will overwrite some files. Proceed?" -n 1 -r
	echo
	if [[ ! $REPLY =~ ^[Yy]$ ]]; then
		exit 1
	fi
fi

#######################
#Shall we play a game?#
#######################

#Download and prep the lastest list of TLDs from IANA
if [ -s ./all_tlds.txt ]; then
	rm ./all_tlds.txt
fi
wget https://data.iana.org/TLD/tlds-alpha-by-domain.txt -O ./all_tlds.txt
vi -c ':1d' -c ':%s/^/\\[\.\]/g' -c ':wq' all_tlds.txt

#Prep packet filter for masscan. If you are using something else, you MUST do this manually.
if [ "$MACOS" != 1 ]; then
	iptables -A INPUT -p tcp --dport 40000:41023 -j DROP
else
	cp /etc/pf.conf /etc/pf.bak
	echo 'block in proto tcp from any to any port 40000 >< 41024' >>/etc/pf.conf
	pfctl -f /etc/pf.conf
fi

#Read in list of CIDR networks from specified file:
while read -r CIDR; do
	echo "$CIDR"
	#make results directories named after subnet:
	DIRNAME=$(sed -e 's/\//_/g' <<<"$CIDR")
	echo "Creating results directory for $CIDR. . ."
	mkdir -p ./results/"$DIRNAME"

	#Start Masscan. Write to binary file so users can --readscan it to whatever they need later:
	echo -e "\n*** Firing ScanCannon. Please keep arms and legs inside the chamber at all times ***"
	masscan -c scancannon.conf --open --source-port 40000-41023 -oB ./results/"$DIRNAME"/masscan_output.bin "$CIDR"
	masscan --readscan ./results/"$DIRNAME"/masscan_output.bin -oL ./results/"$DIRNAME"/masscan_output.txt

	if [ ! -s ./results/"$DIRNAME"/masscan_output.txt ]; then
		echo -e "\nNo IPs are up; skipping nmap. This was a big waste of time.\n"
	fi
	#Consolidate IPs and open ports for each IP:
	awk '/open/ {print $4,$3,$2,$1}' ./results/"$DIRNAME"/masscan_output.txt | awk '
			/.+/{
				if (!($1 in Val)) { Key[++i] = $1; }
				Val[$1] = Val[$1] $2 ",";
				}
		END{
			for (j = 1; j <= i; j++) {
				printf("%s:%s\n%s",  Key[j], Val[Key[j]], (j == i) ? "" : "");
			}
		}' | sed 's/,$//' >>./results/"$DIRNAME"/hosts_and_ports.txt

	#Run in-depth nmap enumeration against discovered hosts & ports, and output to all formats
	#First we have to do a blind UDP nmap scan of common ports, as masscan does not support UDP. Note we Ping here to reduce scan time.
	echo -e "\nStarting DNS, SNMP and VPN scan against all hosts"
	#nmap -v --open -sV --version-light -sU -T3 -p 53,161,500 -oA ./results/"$DIRNAME"/nmap_"$DIRNAME"_udp "$CIDR"
	#Then nmap TCP against masscan-discovered hosts:
	while read -r TARGET; do
		IP=$(echo "$TARGET" | awk -F: '{print $1}')
		PORT=$(echo "$TARGET" | awk -F: '{print $2}')
		FILENAME=$(echo "$IP" | awk '{print "nmap_"$1}')
		echo -e "\nBeginning in-depth TCP scan of $IP on port(s) $PORT:\n"
		nmap -v --open -sV --version-light -sT -O -Pn -T3 -p "$PORT" -oA ./results/"$DIRNAME"/"$FILENAME"_tcp "$IP"
	done <./results/"$DIRNAME"/hosts_and_ports.txt

	#Generate lists of Hosts:Ports hosting Interesting Services™️ for importing into cred stuffers (or other tools)
	mkdir -p ./results/"$DIRNAME"/interesting_servers/
	mkdir -p ./results/all_interesting_servers/
	#(if you add to this service list, make sure you also add it to the master file generation list at the end.)
	for SERVICE in domain msrpc snmp netbios-ssn microsoft-ds isakmp l2f pptp ftp sftp ssh telnet http ssl https; do
		RESULT=$(grep -h -o -E ".+ \d?\d?\d?\d\d/open/..p//$SERVICE" ./results/"$DIRNAME"/*.gnmap)
		if [ -n "$RESULT" ]; then
			SERVIP=$(echo "$RESULT" | tr -d '\n' < <(awk -F" " '{print $2}'))
			SERVPORT=$(echo "$RESULT" | grep -o -E "\d?\d?\d?\d\d/open/..p//$SERVICE" | awk -F"/" '{print $1}')
		fi
		if [ -n "$SERVIP" ]; then
			ECHO "$SERVIP":"$SERVPORT" | tee ./results/"$DIRNAME"/interesting_servers/"$SERVICE"_servers.txt >> ./results/all_interesting_servers/all_"$SERVICE"_servers.txt
			unset SERVIP
			unset SERVPORT
		fi
	done

	#Generate list of discovered sub/domains for this subnet.
	echo "Root Domain,IP,CIDR,AS#,IP Owner" | tee ./results/"$DIRNAME"/resolved_root_domains.csv >>./results/all_root_domains.csv
	while read -r TLD; do
		grep -E -i "$TLD" ./results/"$DIRNAME"/*.gnmap | awk -F[\(\)] '{print $2}' | sort -u | tee ./results/"$DIRNAME"/resolved_subdomains.txt >>./results/all_subdomains.txt
	done <./all_tlds.txt
	while read -r DOMAIN; do
		DIG=$(dig "$DOMAIN" +short)
		WHOIS=$(whois "$DIG" | awk -F':[ ]*' '
			/CIDR:/ { cidr = $2 };
			/Organization:/ { org = $2};
			/OriginAS:/ { print cidr","$2","org}')
		echo "$DOMAIN"",""$DIG"",""$WHOIS" | tee ./results/"$DIRNAME"/resolved_root_domains.csv >>./results/all_root_domains.csv
	done < <(awk -F. '{ print $(NF-1)"."$NF }' ./results/"$DIRNAME"/resolved_subdomains.txt)
done < "$1"


#Restore packet filter backup
echo -e "\nAll scans completed. Reverting packet filter configuration. . . "
if [ "$MACOS" != 1 ]; then
	iptables -D INPUT -p tcp --dport 40000:41023 -j DROP
else
	mv /etc/pf.bak /etc/pf.conf
	pfctl -q -f /etc/pf.conf
fi

#Report unresponsive networks:
comm -3 <(printf "%s\n" ./*/*/*gnmap | sed 's/\/[^\/]+$//' | sort -u) <(printf "%s\n" ./*/*) | awk -F"/" '{print $2}' | sed 's/\_/\//g' >>./results/dead_networks.txt

##############
#Housekeeping#
##############
echo -e "\nPerforming cleanup. . . "
#while read -r MASSFILE; do
	#rm "$MASSFILE"
#done < <(find ./results -name masscan_output.txt)
rm ./paused.conf
for DIRECTORY in $(echo ./results/*/); do
	#mkdir -p "$DIRECTORY"{nmap_files,gnmap_files,nmap_xml_files}
	mv -f "$DIRECTORY"*.nmap "$DIRECTORY"nmap_files/ 2>/dev/null
	mv -f "$DIRECTORY"*.gnmap "$DIRECTORY"gnmap_files/ 2>/dev/null
	mv -f "$DIRECTORY"*.xml "$DIRECTORY"nmap_xml_files/ 2>/dev/null
	rm -rf ./results/all_interesting_servers/*_files   #fix this fix. 
done
chmod -R 776 ./results

echo -e "\nPowering down ScanCannon. Please check for any personal belongings before exiting the chamber."