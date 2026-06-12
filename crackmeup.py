import json
import subprocess
import argparse
import sys
import datetime
import re
import time
import pandas as pd
import regex as re2
import warnings
import numpy as np
import os

warnings.simplefilter(action='ignore', category=FutureWarning)

# Default paths
DEFAULT_RULES_PATH = "/home/colonelsanders/hashcat-files/rules/"
DEFAULT_WORDLIST_PATH = "/home/colonelsanders/hashcat-files/wordlists/"

# Complexity table for password analysis
COMPLEXITY_TABLE = {
    'complexity': ['loweralpha', 'upperalpha', 'numeric', 'special', 'loweralphanum', 'upperalphanum', 'mixedalpha',
                   'loweralphaspecial', 'upperalphaspecial', 'specialnum', 'mixedalphanum', 'loweralphaspecialnum',
                   'mixedalphaspecial', 'upperalphaspecialnum', 'mixedalphaspecialnum'],
    'regex': ['^[a-z]+$', '^[A-Z]+$', '^[0-9]+$', '^[\p{posix_punct}]+$', '^[a-z0-9]+$', '^[A-Z0-9]+$',
              '^[a-zA-Z]+$', '^[a-z\p{posix_punct}]+$', '^[A-Z\p{posix_punct}]+$', '^[\p{posix_punct}0-9]+$',
              '^[a-zA-Z0-9]+$', '^[a-z\p{posix_punct}0-9]+$', '^[A-Za-z\p{posix_punct}]+$',
              '^[A-Z\p{posix_punct}0-9]+$', '^[A-Za-z\p{posix_punct}0-9]+$']
}

def analyze_complexity(password):
    """Analyzes password complexity based on predefined regex patterns."""
    for i, regex in enumerate(COMPLEXITY_TABLE['regex']):
        if re2.match(regex, password):
            return COMPLEXITY_TABLE['complexity'][i]
    return "unknown"

def load_session(session_path):
    """Loads session data from a JSON file."""
    if session_path and os.path.exists(session_path):
        with open(session_path, 'r') as f:
            data = json.load(f)
            # Ensure new keys exist for backward compatibility
            if "completed_masks" not in data:
                data["completed_masks"] = []
            return data
    return {
        "completed": [],
        "completed_masks": [],
        "pot_file_list": [],
        "hash_file": None,
        "mode": None,
        "hash_dir": None
    }

def save_session(session_path, session_data):
    """Saves session data to a JSON file."""
    if session_path:
        with open(session_path, 'w') as f:
            json.dump(session_data, f, indent=4)

# Resource configuration
EFFORT_LEVELS = {
    'low': {
        'wordlists': ["rockyou.txt", "InsideProFull"],
        'rules': ["best64.rule", "hob064.rule", "yubaba64.rule"]
    },
    'medium': {
        'wordlists': [
            "rockyou.txt", "InsideProFull", 
            "hk_hlm_founds.txt", "kaonashi.txt"
        ],
        'rules': [
            "best64.rule", "hob064.rule", "yubaba64.rule",
            "d3ad0ne.rule", "haku34K.rule", "kamaji34K.rule"
        ]
    },
    'high': {
        'wordlists': [
            "rockyou.txt", "InsideProFull", 
            "hk_hlm_founds.txt", "kaonashi.txt", "crackstation.txt", "weakpass_3"
        ],
        'rules': [
            "best64.rule", "hob064.rule", "yubaba64.rule",
            "d3ad0ne.rule", "haku34K.rule", "kamaji34K.rule", "d3adhob0.rule",
            "pantagrule.popular.rule"
        ]
    }
}

pot_file_list = []

# Hashcat tuning constants
# Note: NTLM (1000) and Kerberos (13100/18200) are treated as FAST hashes 
# to ensure maximum performance during AD audits.
SLOW_HASH_MODES = [
    '3200',   # bcrypt
    '1800',   # sha512crypt
    '1400',   # sha256crypt
    '10900',  # PBKDF2-HMAC-SHA256
    '16800',  # WPA/WPA2 PMKID
    '2500',   # WPA/WPA2 Handshake
    '19600',  # Kerberos 5, etype 17/18 (AES) - Slower than RC4
    '19700'   # Kerberos 5, etype 17/18 (AES) - Slower than RC4
]

def get_hashcat_mask(password):
    """Converts a password into its hashcat mask representation."""
    mask = ""
    for char in password:
        if char.islower():
            mask += "?l"
        elif char.isupper():
            mask += "?u"
        elif char.isdigit():
            mask += "?d"
        else:
            mask += "?s"
    return mask

def perform_mask_analysis(passwords):
    """Analyzes a list of passwords and returns the top 10 masks."""
    if not passwords:
        return []
    
    masks = [get_hashcat_mask(p) for p in passwords]
    mask_counts = pd.Series(masks).value_counts().head(10)
    return mask_counts.reset_index().values.tolist()

def create_csv_all_data(analyze_file, out_file):
    """Generates a CSV report with password analysis from hashcat output."""
    results = []
    
    try:
        with open(analyze_file, "r") as f:
            for line in f:
                temp = line.strip().split(':')
                if len(temp) < 3:
                    continue
                
                password = temp[2]
                complexity = analyze_complexity(password)
                results.append({
                    'username': temp[0],
                    'hash': temp[1],
                    'password': password,
                    'length': len(password),
                    'complexity': complexity
                })
    except FileNotFoundError:
        print(f"Error: {analyze_file} not found.")
        return

    df = pd.DataFrame(results)
    if not df.empty:
        df.to_csv(out_file, index=False)
    else:
        print(f"No results found in {analyze_file}")

def build_hc_post_command(mode_num, combined_file, hash_dir, hash_file):
    now = datetime.datetime.now()
    hash_loc = os.path.join(hash_dir, hash_file)
    hc_results_file = os.path.join(hash_dir, f"temp-{hash_file}-{now.strftime('%Y-%m-%d-%H-%M-%S')}.txt")
    
    hc_cmd = [
        'hashcat', '-m', str(mode_num), '--show', '--username', hash_loc,
        f'--potfile-path={combined_file}', '-o', hc_results_file
    ]
    
    csv_name = os.path.join(hash_dir, f"hashcat-{hash_file}-{now.strftime('%Y-%m-%d-%H-%M-%S')}.csv")
    return csv_name, hc_results_file, hc_cmd

def build_hc_mask_command(mask, mode_num, hash_dir, hash_file, workload='auto'):
    """Builds a hashcat mask attack command (-a 3)."""
    now = datetime.datetime.now()
    
    # Clean mask name for filename
    mask_clean = re.sub('[^?a-zA-Z0-9]', '_', mask).replace('?', '')
    pot_loc = os.path.join(hash_dir, f"mask_attack-{mask_clean}-{now.strftime('%Y-%m-%d-%H-%M-%S')}.pot")
    hash_loc = os.path.join(hash_dir, hash_file)
    
    mode_str = str(mode_num)
    if workload == 'auto':
        w_profile = '2' if mode_str in SLOW_HASH_MODES else '3'
    else:
        w_profile = workload

    hc_cmd = [
        'hashcat', hash_loc, '-m', mode_str, '-a', '3',
        f'--potfile-path={pot_loc}',
        '-w', w_profile,
        mask
    ]

    if mode_str not in SLOW_HASH_MODES:
        hc_cmd.append('-O')

    log_name = f"hashcat-mask-{mask_clean}-{now.strftime('%Y-%m-%d-%H-%M-%S')}.log"

    return log_name, hc_cmd, pot_loc

def build_hc_command(wordlist_file, rule, mode_num, pot_file, hash_dir, hash_file, rules_path, wordlist_path, use_timestamp=True, workload='auto'):
    now = datetime.datetime.now()
    
    wl_base = re.sub('\.txt', '', wordlist_file)
    rule_base = re.sub('\.rule', '', rule)
    
    if use_timestamp:
        pot_loc = os.path.join(hash_dir, f"{pot_file}-{wl_base}-{rule_base}-{now.strftime('%Y-%m-%d-%H-%M-%S')}.pot")
    else:
        pot_loc = os.path.join(hash_dir, f"{pot_file}.pot")
        
    hash_loc = os.path.join(hash_dir, hash_file)
    
    # Auto-tuning logic
    mode_str = str(mode_num)
    if workload == 'auto':
        w_profile = '2' if mode_str in SLOW_HASH_MODES else '3'
    else:
        w_profile = workload

    hc_cmd = [
        'hashcat', hash_loc, '-m', mode_str,
        f'--potfile-path={pot_loc}',
        '-w', w_profile,
        '-r', os.path.join(rules_path, rule),
        os.path.join(wordlist_path, wordlist_file)
    ]

    # Add optimized kernels flag for fast hashes if not specifically disabled
    if mode_str not in SLOW_HASH_MODES:
        hc_cmd.append('-O')

    log_name = f"hashcat-{wl_base}-{rule_base}-{now.strftime('%Y-%m-%d-%H-%M-%S')}.log"

    return log_name, hc_cmd, pot_loc

def count_length(password):
    return len(password)

def unique(list1):
    x = np.array(list1)
    return np.unique(x)

def main():
    parser = argparse.ArgumentParser(description='CrackMeUp: Hashcat Wrapper with Session Management')
    parser.add_argument('-m', '--mode', required=True, help='Hashcat mode')
    parser.add_argument('-d', '--hash_dir', required=True, help='Directory for hashes and outputs')
    parser.add_argument('-p', '--pot', required=True, help='Base name for pot files')
    parser.add_argument('-f', '--hash_file', required=True, help='Hash file to crack')
    parser.add_argument('-a', '--all', action='store_true', help='Retry all against wordlist & rules (uses timestamps for potfiles)')
    parser.add_argument('-s', '--session', help='Path to session file (JSON) to resume or start')
    parser.add_argument('-e', '--effort', choices=['low', 'medium', 'high'], default='medium', help='Effort level (default: medium)')
    parser.add_argument('-w', '--workload', default='auto', choices=['auto', '1', '2', '3', '4'], help='Hashcat workload profile (default: auto)')
    parser.add_argument('--auto_mask', action='store_true', help='Automatically run mask attacks for patterns found > threshold')
    parser.add_argument('--mask_threshold', type=int, default=20, help='Minimum occurrences to trigger an automated mask attack (default: 20)')
    parser.add_argument('--rules_path', default=DEFAULT_RULES_PATH, help='Path to hashcat rules')
    parser.add_argument('--wordlist_path', default=DEFAULT_WORDLIST_PATH, help='Path to hashcat wordlists')

    args = parser.parse_args()

    hash_dir = args.hash_dir
    hash_file = args.hash_file
    hc_mode = args.mode
    pot_file = args.pot
    session_path = args.session
    rules_path = args.rules_path
    wordlist_path = args.wordlist_path
    effort = args.effort
    workload = args.workload
    auto_mask = args.auto_mask
    mask_threshold = args.mask_threshold

    # Ensure session file is in the hash_dir if a relative path/filename is provided
    if session_path and not os.path.isabs(session_path):
        session_path = os.path.join(hash_dir, session_path)

    # Load or initialize session
    session = load_session(session_path)
    if session_path and not session["hash_file"]:
        session["hash_file"] = hash_file
        session["mode"] = hc_mode
        session["hash_dir"] = hash_dir
        save_session(session_path, session)

    now = datetime.datetime.now()
    hashcat_session_log = os.path.join(hash_dir, f"hashcat_session_log_{now.strftime('%Y_%m_%d_%H_%M_%S')}.json")

    selected_wordlists = EFFORT_LEVELS[effort]['wordlists']
    selected_rules = EFFORT_LEVELS[effort]['rules']

    total_hashes_cracked = 0
    start_run_time = time.time()
    skipped_count = 0
    combo_stats = []
    current_process = None

    try:
        for wordlist_file in selected_wordlists:
            for rule in selected_rules:
                combo = f"{wordlist_file}:{rule}"
                if combo in session["completed"]:
                    skipped_count += 1
                    continue

                print(f"\n--- Processing [{effort.upper()}]: {wordlist_file} with {rule} ---")
                
                logfile_name, hc_cmd, pot_loc = build_hc_command(
                    wordlist_file, rule, hc_mode, pot_file, hash_dir, hash_file, 
                    rules_path, wordlist_path, use_timestamp=args.all, workload=workload
                )

                logfile = os.path.join(hash_dir, logfile_name)
                start_time = int(time.time() * 1000)

                print(f"Executing: {' '.join(hc_cmd)}")
                
                try:
                    current_process = subprocess.Popen(hc_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    with open(logfile, 'wb') as f:
                        while True:
                            chunk = current_process.stdout.read(4096)
                            if not chunk:
                                break
                            sys.stdout.write(chunk.decode('utf-8', 'ignore'))
                            f.write(chunk)
                    current_process.wait()
                    current_process = None
                except Exception as e:
                    print(f"Error executing hashcat: {e}")
                    current_process = None
                    continue

                end_time = int(time.time() * 1000)
                duration_sec = (end_time - start_time) / 1000

                # Analyze results
                results = []
                num_lines = 0
                if os.path.exists(pot_loc):
                    with open(pot_loc, 'r') as fp:
                        for line in fp:
                            num_lines += 1
                            temp = line.strip().split(':')
                            if len(temp) >= 2:
                                password = temp[1]
                                results.append({
                                    'password': password,
                                    'length': len(password),
                                    'complexity': analyze_complexity(password)
                                })

                total_hashes_cracked += num_lines
                efficiency = num_lines / duration_sec if duration_sec > 0 else 0
                combo_stats.append({
                    'combo': combo,
                    'cracks': num_lines,
                    'efficiency': efficiency
                })

                res_df = pd.DataFrame(results)
                summary_json = []
                if not res_df.empty:
                    summary_json = res_df.groupby(['length', 'complexity']).size().reset_index().rename(
                        columns={0: 'complexity_count'}).to_dict(orient="records")

                log_entry = {
                    "start_time": start_time,
                    "end_time": end_time,
                    "effort_level": effort,
                    "wordlist": wordlist_file,
                    "rule": rule,
                    "hashes-cracked": num_lines,
                    "efficiency_cps": round(efficiency, 4),
                    "results": summary_json
                }

                with open(hashcat_session_log, 'a') as hs:
                    hs.write(json.dumps(log_entry) + "\n")

                session["completed"].append(combo)
                if pot_loc not in session["pot_file_list"]:
                    session["pot_file_list"].append(pot_loc)
                save_session(session_path, session)

        if auto_mask:
            # Re-read all passwords found so far to get accurate mask counts
            all_p = []
            for p in session["pot_file_list"]:
                if os.path.exists(p):
                    with open(p, 'r') as f:
                        for line in f:
                            t = line.strip().split(':')
                            if len(t) >= 2: all_p.append(t[1])
            
            if all_p:
                mask_freq = pd.Series([get_hashcat_mask(p) for p in all_p]).value_counts()
                high_freq_masks = mask_freq[mask_freq >= mask_threshold].index.tolist()
                
                if high_freq_masks:
                    print(f"\n--- AUTOMATED MASK ATTACK PHASE (Threshold: {mask_threshold}) ---")
                    for mask in high_freq_masks:
                        if mask in session["completed_masks"]:
                            continue
                        
                        print(f"\nTriggering automated attack for mask: {mask}")
                        logfile_name, hc_cmd, pot_loc = build_hc_mask_command(mask, hc_mode, hash_dir, hash_file, workload)
                        
                        logfile = os.path.join(hash_dir, logfile_name)
                        print(f"Executing: {' '.join(hc_cmd)}")
                        
                        try:
                            current_process = subprocess.Popen(hc_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                            with open(logfile, 'wb') as f:
                                while True:
                                    chunk = current_process.stdout.read(4096)
                                    if not chunk: break
                                    sys.stdout.write(chunk.decode('utf-8', 'ignore'))
                                    f.write(chunk)
                            current_process.wait()
                            current_process = None
                        except Exception as e:
                            print(f"Error executing mask attack: {e}")
                            current_process = None
                            continue

                        if os.path.exists(pot_loc):
                            with open(pot_loc, 'r') as fp:
                                mask_cracks = len(fp.readlines())
                                total_hashes_cracked += mask_cracks
                                print(f"Mask {mask} cracked {mask_cracks} additional hashes!")

                        session["completed_masks"].append(mask)
                        if pot_loc not in session["pot_file_list"]:
                            session["pot_file_list"].append(pot_loc)
                        save_session(session_path, session)

    except KeyboardInterrupt:
        print("\n\n[!] Interruption detected (Ctrl+C). Cleaning up...")
        if current_process:
            current_process.terminate()
            try:
                current_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                current_process.kill()
        save_session(session_path, session)
        print("[+] Progress saved. Generating partial report...")

    end_run_time = time.time()
    
    # Run Summary
    print("\n" + "="*40)
    print("RUN SUMMARY")
    print("="*40)
    print(f"Effort Level:   {effort.upper()}")
    print(f"Workload:       {workload} (Mode: {hc_mode})")
    print(f"Time Elapsed:   {datetime.timedelta(seconds=int(end_run_time - start_run_time))}")
    print(f"Hashes Cracked: {total_hashes_cracked}")
    print(f"Combos Skipped: {skipped_count}")
    
    if combo_stats:
        best_combo = max(combo_stats, key=lambda x: x['efficiency'])
        print(f"Most Efficient: {best_combo['combo']} ({best_combo['efficiency']:.2f} cracks/sec)")
    print("="*40)

    # Post-processing: Combine all potfiles and perform Mask Analysis
    print("\n--- Finalizing: Intelligence & Reports ---")
    all_passwords = []
    temp_hash_list = []
    for pot in session["pot_file_list"]:
        if os.path.exists(pot):
            with open(pot, 'r') as infile:
                for line in infile:
                    line = line.strip()
                    temp_hash_list.append(line)
                    temp = line.split(':')
                    if len(temp) >= 2:
                        all_passwords.append(temp[1])

    # Mask Analysis & Automated Attacks
    if all_passwords:
        mask_freq = pd.Series([get_hashcat_mask(p) for p in all_passwords]).value_counts()
        top_masks = mask_freq.head(10).reset_index().values.tolist()
        
        if top_masks:
            print("\nTOP 10 PASSWORD MASKS FOUND")
            print("-" * 30)
            print(f"{'Mask':<20} | {'Count':<5}")
            print("-" * 30)
            for mask, count in top_masks:
                print(f"{mask:<20} | {count:<5}")
            print("-" * 30)

    unique_hash_list = unique(temp_hash_list)
    combined_file = os.path.join(hash_dir, f"hashcat_combined_{now.strftime('%Y_%m_%d_%H_%M_%S')}.txt")

    with open(combined_file, "w") as results_file:
        for item in unique_hash_list:
            results_file.write(item + "\n")

    # Generate final CSV report
    csv_name, hc_results_file, hc_cmd = build_hc_post_command(hc_mode, combined_file, hash_dir, hash_file)
    
    print(f"\nGenerating final results CSV with: {' '.join(hc_cmd)}")
    subprocess.run(hc_cmd)

    create_csv_all_data(hc_results_file, csv_name)
    print(f"Final report generated: {csv_name}")

if __name__ == '__main__':
    main()