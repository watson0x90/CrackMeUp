# CrackMeUp
Analyze passwords based upon multiple rules and wordlists

## Usage
```
    -m: The password hash type (ntlm: 1000)
    -d`: Directory where the the hashes are
    -p: Pot file to store cracked password. Will be placed in the hashes directory you created. Note: Just the beginning of the file name, exclude `.pot`
    -f: Name of the hashes file.
```

## Example Usage
```bash
python3 crackmeup.py -m 1000 -d /opt/tools/hashcat-files/hashes/2023PWAudit -f 20231028-ad-int-hashes.txt -p ad_name-ntlm
```
