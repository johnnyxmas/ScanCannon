#!/bin/bash

echo -e "ScanCannon v0.89\n"

#Help Text:
function helptext {
	echo "usage: scancannon.sh [file . . .]"
	echo "Requires one argument: a file containing a line-separated list of CIDR addresses"
}

#Make sure an non-empty file is supplied as an argument:
if [ "$#" -ne 1 ]; then
	echo  "ERROR: Invalid argument(s)."
	helptext >&2
	exit 1
elif [ ! -s $1 ]; then
	echo "ERROR: CIDR file is empty"
	helptext >&2
	exit 1
fi

#Check for root (both masscan & nmap require root for certain activities):
if [ "$(id -u)" != "0" ]; then
	echo "ERROR: This script must be run as root"
	helptext >&2
	exit 1
fi

#######################
#Shall we play a game?#
#######################

#Download and prep the lastest list of TLDs from IANA
if [ -s ./all_tlds.txt ]; then
	rm ./all_tlds.txt
	wget https://data.iana.org/TLD/tlds-alpha-by-domain.txt -O ./all_tlds.txt
        sed -i -e '1d' all_tlds.txt -e s/^/\\[\.\]/g
else
	wget https://data.iana.org/TLD/tlds-alpha-by-domain.txt -O ./all_tlds.txt
	sed -i -e '1d' all_tlds.txt -e s/^/\\[\.\]/g
fi

#Read in list of CIDR networks from specified file:
for CIDR in $(cat $1); do
	#make results directory named after subnet:
	DIRNAME=$(echo $CIDR | sed -e 's/\//_/g');
	echo "Creating results directory for $CIDR. . .";
	mkdir -p ./results/$DIRNAME;

	#Start Masscan:
	iptables -A INPUT -p tcp --dport 60000 -j DROP;
	echo -e "\n*** Firing ScanCannon. Please keep arms and legs inside the chamber at all times ***";
	masscan --open --banners --source-port 60000 -p0-65535 --max-rate 20000 -oB ./results/$DIRNAME/masscan.bin $CIDR; masscan --readscan ./results/$DIRNAME/masscan.bin -oL ./results/$DIRNAME/masscan-output.txt;

	if [ ! -s ./results/$DIRNAME/masscan-output.txt ]; then
        	echo -e "\nNo IPs are up; skipping nmap. This was a big waste of time.\n"
	else
		#Consolidate IPs and open ports for each IP, then write to a file because files are handy:
		awk '/open/ {print $4,$3,$2,$1}' ./results/$DIRNAME/masscan-output.txt |  awk '
    			/.+/{
        			if (!($1 in Val)) { Key[++i] = $1; }
        			Val[$1] = Val[$1] $2 ",";
    				}
    		END{
        		for (j = 1; j <= i; j++) {
          		 printf("%s:%s\n%s",  Key[j], Val[Key[j]], (j == i) ? "" : "\n");
        		}
    		}' | sed 's/,$//' > ./results/$DIRNAME/discovered_hosts.txt #remove trailing comma, write to file

		#Run in-depth nmap enumeration against discovered hosts & ports:
		for TARGET in $(cat ./results/$DIRNAME/discovered_hosts.txt); do
    	   		IP=$(echo $TARGET | awk -F: '{print $1}');
        		PORT=$(echo $TARGET | awk -F: '{print $2}');
        		FILENAME=$(echo $IP | awk '{print "nmap_"$1}');
        		nmap -vv -sV --version-intensity 5 -sT -O --max-rate 15000 -Pn -T3 -p $PORT -oA ./results/$DIRNAME/$FILENAME $IP;
		done

		#Generate list of discovered sub/domains for this subnet
        	for TLD in `cat ./all_tlds.txt`; do
                	cat ./results/$DIRNAME/*.gnmap | egrep -i $TLD\) | awk -F[\(\)] '{print $2}' | sort -u  >> ./results/$DIRNAME/resolved_subdomains.txt;
		done
		echo "Root Domain,IP,CIDR,AS#,IP Owner" > ./results/$DIRNAME/resolved_root_domains.csv
		for DOMAIN in `cat ./results/$DIRNAME/resolved_subdomains.txt | awk -F. '{ print $(NF-1)"."$NF }' | sort -u`; do
			DIG=$(dig $DOMAIN +short);
			WHOIS=$(whois 213.171.195.105 | awk -F':[ ]*' '
      			/CIDR:/ { cidr = $2 };
      			/Organization:/ { org = $2};
      			/OriginAS:/ { print cidr","$2","org}')
			echo $DOMAIN","$DIG","$WHOIS >> ./results/$DIRNAME/resolved_root_domains.csv;
		done
	fi
done

#Generate list subnets with no alive hosts
comm -3 <(printf "%s\n" */*/*gnmap | sed -r 's/\/[^\/]+$//' | sort -u) <(printf "%s\n" */*) | awk -F"/" '{print $2}' | sed 's/\_/\//g' >> ./results/dead_subnets.txt

#Concatenate list of all discovered sub/domains
for i in `find ./results -name resolved_subdomains.txt`; do
	cat $i >> ./results/all_subdomains.txt;
done
echo "Root Domain,IP,AS CIDR" > ./results/all_root_domains.txt
for i in `find ./results -name resolved_root_domains.csv`; do
	cat $i | sed '1d' >> ./results/all_root_domains.txt;
done

for i in `find ./results -name discovered.csv`; do
        cat $i >> ./results/all_IPs_and_ports.csv;
done

chmod -R 777 results #remove file restrictions

echo -e "\nJob complete. Please check for any personal belongings before exiting the chamber."
