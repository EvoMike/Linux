#!/bin/bash

# This script will be able to enumerate several common places of persistence within the Linux filesystem
# Before the script starts the enumeration it will need to know where to find files for use when searching through multiple systems.
# The first thing I want to assign is the file path for the list of systems that will be enumerated. Eventually I will update this to
# take user input and ask whether the user wants to use a file or a single IP for the interrogation, as well as input validation.

echo "Please input the path of the file that identifies the target systems"
read hostIPList

# The next thing we need to know is how many lines the user would like to list for the passwd, shadow, and group file enumeration.

echo "How many lines would you like to view from the passwd, shadow, and group files?"
read fileLineNum

# Now we need to find out how many lines the user would like to view from the log files. I put this and the file line numbers as two
# different variables just because you don't need very many lines from the above files to get situational awareness, but you may need
# many lines from a log file. Eventually I would like to add in some kind of searching filter where the user can look through a
# specified time range for the log files.

echo "How many lines would you like to view from the log files?"
read logFileLineNum

# Next we are asking for the file that the user wants to the information to be saved as. The naming convention SHOULD be descriptive
# enough to be able to continually save new baselines and enumerations, but I'm also not your mother. Name it what you want.

echo "Where would you like this script to save your enumeration information?"
read enumFileName

# The last thing we will need is to get credentials from the user. These credentials will be need to ssh into the systems to grab
# information from them. These credentials will need to be admin credentials or some of the commands will fail. It should also work
# if the user is in the sudoers file on that machine, but this hasn't been tested yet and may need the script to enter the password
# of the user again in order to access things. If this is the case it will just require the script to enter the password an extra time.

# echo "What is the username that will be used?"
# read username
# echo "What is the password for the input username?"
# read password

# The first thing that the script will check the filesystem for any KNOWN Indicators of Compromise (IOCs) that are listed within a file.
# The IOC file should contain only file names and extensions if applicable, not the full path. I'm actually thinking this should be the
# last thing done because it takes so long. Since bash will write to the file each time it finishes an action the user should be able
# to view the file contents while the filesystem IOC search is being done.

# IOCfile = /root/Documents/IOCfile.txt
# for IOC in $IOCfile
# do { }
# done

# This part of the script will search through the passwd, shadow, and group files as well as listing the home directories in order to see 
# if an unauthorized account or group has been made. This part of the script will require root privilages in order to read the shadow file.

for hostIP in $(cat $hostIPList)
do {
	echo "******************************************"
	echo "******************************************"
	echo "The last $fileLineNum lines of /etc/passwd on $hostIP are:"
	echo "******************************************"
	echo "******************************************"
	tail -$fileLineNum /etc/passwd; echo $password
	echo "******************************************"
	echo "******************************************"
	echo "The last $fileLineNum lines of /etc/shadow on $hostIP are:"
	echo "******************************************"
	echo "******************************************"
	tail -$fileLineNum /etc/shadow; echo $password
	echo "******************************************"
	echo "******************************************"
	echo "The last $fileLineNum lines of /etc/group on $hostIP are:"
	echo "******************************************"
	echo "******************************************"
	tail -$fileLineNum /etc/group; echo $password

# This part of the script will display a list of computers that have been in contact with the host recently as well as a list of network
# connections to include listening ports.

	echo "******************************************"
	echo "******************************************"
	echo "The ARP cache in memory on $hostIP contains:"
	echo "******************************************"
	echo "******************************************"
	arp -a #'\r\n'; echo $userPassword
	echo "******************************************"
	echo "******************************************"
	echo "The following connections are active on $hostIP"
	echo "******************************************"
	echo "******************************************"
	netstat -tupan #'\r\n'; echo $userPassword

# This part of the script will display a list of recurring system jobs, recurring user jobs, and scheduled user tasks

# This part of the script will check varying log files for signs of persistence.

# /var/log/dpkg.log shows when a package was installed. Use these logs to see if there have been any malicious or unauthorized packages
# have been installed since the time of suspected infection or the time in question. This will need to be edited to use a time function
# instead of just asking for the number of lines in the future.

	echo "******************************************"
	echo "******************************************"
	echo "The last $logFileLineNum lines of dpkg.log on $hostIP are:"
	echo "******************************************"
	echo "******************************************"
	tail -$logFileLineNum /var/log/dpkg.log

# /var/log/auth.log shows who logs in and when they logged in and out. This log output will be useful to verify the usernames that have
# accessed a box and to view which machines have been accessed by specific users.

	echo "******************************************"
	echo "******************************************"
	echo "The last $logFileLineNum lines of auth.log on $hostIP are:"
	echo "******************************************"
	echo "******************************************"
	tail -$logFileLineNum /var/log/auth.log

# /var/log/secure shows all authorization logs and will show authentication failures. This may be useful to determine where the initial
# point of compromise is or which machines the attacker was trying to access (if unsuccessful).

	echo "******************************************"
	echo "******************************************"
	echo "The last $logFileLineNum lines of the secure log on $hostIP are:"
	echo "******************************************"
	echo "******************************************"
	tail -$logFileLineNum /var/log/secure

# /var/log/messages shows general system activity logs. These logs will show something important, but they aren't your mothers logs.

	echo "******************************************"
	echo "******************************************"
	echo "The last $logFileLineNum lines of the messages log on $hostIP are:"
	echo "******************************************"
	echo "******************************************"
	tail -$logFileLineNum /var/log/messages

# /var/log/syslog shows logs from applications and services. This means that any new applications or services that an attacker starts
# will show up here. 

	echo "******************************************"
	echo "******************************************"
	echo "The last $logFileLineNum lines of the syslog on $hostIP are:"
	echo "******************************************"
	echo "******************************************"
	tail -$logFileLineNum /var/log/syslog

# /var/log/boot.log shows logs from the system boot process. Hopefully nothing unusual is found here because if an attacker establishes
# persistence within the boot process it's probably time to burn it all down and start again from scratch.

	echo "******************************************"
	echo "******************************************"
	echo "The last $logFileLineNum lines of boot.log on $hostIP are:"
	echo "******************************************"
	echo "******************************************"
	tail -$logFileLineNum /var/log/boot.log

# /var/log/btmp shows ONLY failed logins. This will give an output similar to the auth.log file but will narrow the scope to only failed
# logins.

	echo "******************************************"
	echo "******************************************"
	echo "The last $logFileLineNum lines of the btmp on $hostIP are:"
	echo "******************************************"
	echo "******************************************"
	tail -$logFileLineNum /var/log/btmp

# This part of the script will get a 'baseline' of the system that will include a listing of all files as well as their file hashes. This
# can be used to compare against a known good baseline or to set an initial baseline on a system so you can rebaseline it again later and
# compare the two to see changes. Since this part of the script takes so long I will leave two of the hasing algorithms commented out so
# they can be selected or deselected when needed.

	echo "******************************************"
	echo "******************************************"
	echo "The File System baseline of $hostIP follows:"
	echo "******************************************"
	echo "******************************************"
	for files in $(find / -name "*")
	do {
		md5sum $files 2>/dev/null
		#sha1sum $files 2>/dev/null
		#sha256sum $files 2>/dev/null
	}
	done

# This part of the script will print out a copy of the iptables rules. I may use an additional command to check for other types of network
# filtering later on.

} > $enumFileName
done
