# CrackMeUp
## Overview
It was created to fill a unique need to answer the question of how long it might take to crack passwords with certain wordlists and rule sets. With this information, you can suggest how a password policy might be improved and how to educate users on creating better passwords. The script will attempt to re-crack passwords when it uses a wordlist and ruleset. When the script finishes, a `.csv` file will be created with information gahtered during the password cracking process with hashcat.

## Requirements
1. Hashcat installed and in your PATH
2. Python3
3. Install requirements.txt
4. You will be likely using this for NTLM hashes, they must be in the JTR format of:
    - ``` user1:1234:aad3b435b51404eeaad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b:::```     

## Usage
```
    -s: single pass without attempt to crack over and over with each wordlist and ruleset
    -m: The password hash type (ntlm: 1000)
    -d: Directory where the the hashes are
    -p: Pot file to store cracked password. Will be placed in the hashes directory you created. Note: Just the beginning of the file name, exclude `.pot`
    -f: Name of the hashes file.
```

## Example Usage
```bash
python3 crackmeup.py -s -m 1000 -d /opt/tools/hashcat-files/hashes/2023PWAudit -f 20231028-ad-int-hashes.txt -p ad_name-ntlm
```

## Output files
While cracking passwords, multiple files will be created such as:
  - `.log` files for keeping track of hashcat sessions
  - `.pot` files for cracked passwords for each wordlist and ruleset used
  - `.csv` file that will output a full analysis of cracked password based upon each wordlist and ruleset used

It is important to note that you must run the example command above in a **screen** session if you are working over SSH to your password-cracking rig. You will also need to let the password cracking run its course because there is only a recovery or option to analyze passwords after first working through cracking.

## Wordlists & Rule Sets
  - https://weakpass.com/
  - https://github.com/n0kovo/hashcat-rules-collection
  - https://github.com/praetorian-inc/Hob0Rules
