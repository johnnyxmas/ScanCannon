#!/bin/bash

echo -e "ScanCannon v0.6 by J0hnnyXm4s\n"

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

echo -e "Chargin' mah lazer. . .\n"

#Make dir for results files if necessary:
if [ ! -d "results" ]; then
	echo -e "Creating parent results directory. . .\n"
	mkdir results
else
	echo -e "Parent results directory exists. Continuing. . .\n"
fi

#Read in list of CIDR networks from specified file:
for CIDR in $(cat $1); do
	DIRNAME=$(echo $CIDR | sed -e 's/\//_/g');
	#make results directory named after subnet, then cd into it:
	echo "Creating results directory for $CIDR. . ."
	mkdir -p results/$DIRNAME;
	cd results/$DIRNAME;

	#Start Masscan:
	iptables -A INPUT -p tcp --dport 60000 -j DROP;
	echo -e "\n*** Firing ScanCannon. Please keep arms and legs inside the chamber at all times ***"
	masscan --open --banners --source-port 60000 -p0-65535 --max-rate 20000 -oB Output.bin $CIDR; masscan --readscan ./Output.bin -oL ./List-Output.txt;

	if [ ! -s List-Output.txt ]; then
        	echo -e "\nNo IPs are up; skipping nmap. This was a big waste of time.\n"
	else

	#Consolidate IPs and open ports for each IP, then write to a file because files are handy:
	awk '/open/ {print $4,$3,$2,$1}' List-Output.txt |  awk '
    	/.+/{
        	if (!($1 in Val)) { Key[++i] = $1; }
        	Val[$1] = Val[$1] $2 ","; 
    	}
    	END{
        	for (j = 1; j <= i; j++) {
           		printf("%s:%s\n%s",  Key[j], Val[Key[j]], (j == i) ? "" : "\n");       
        	}                                    
    	}' > Up_ip_port.csv

#Run in-depth nmap enumeration against discovered hosts & ports:
		for TARGET in $(cat Up_ip_port.csv); do
    	   		IP=$(echo $TARGET | awk -F: '{print $1}');
        		PORT=$(echo $TARGET | awk -F: '{print $2}' | sed 's/,$//'); #Hack to remove that pesky trailing comma
        		FILENAME=$(echo $IP $PORT | awk '{print $1"_"$2}');
        		nmap -vv -sV --version-intensity 5 -sT -O --max-rate 5000 -Pn -T3 -p $PORT -oA $FILENAME $IP;
		done
	fi
done
echo -e "\nJob complete. Please check for any personal belongings before exiting the chamber."
