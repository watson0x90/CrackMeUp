import json
import subprocess
import getopt
import sys
import datetime
import re
import time
import pandas as pd
import regex as re2
import warnings
import numpy as np
warnings.simplefilter(action='ignore', category=FutureWarning)


rules_path = "/home/colonelsanders/hashcat-files/rules/"
wordlist_path = "/home/colonelsanders/hashcat-files/wordlists/"

rule_files = [
    "best64.rule",
    "hob064.rule",
    "d3ad0ne.rule",
    "d3adhob0.rule",
    "haku34K.rule",
    "kamaji34K.rule",
    "yubaba64.rule",
    "pantagrule.popular.rule"

]

wordlist_files = [
    "rockyou.txt",
    "InsideProFull",
    "hk_hlm_founds.txt",
    "kaonashi.txt",
    "crackstation.txt",
    "weakpass_3"
]

pot_file_list = []

def create_csv_all_data(analyzeFile, outFile):

    complexityTable = {
        'complexity': ['loweralpha', 'upperalpha', 'numeric', 'special', 'loweralphanum', 'upperalphanum', 'mixedalpha',
                       'loweralphaspecial', 'upperalphaspecial', 'specialnum', 'mixedalphanum', 'loweralphaspecialnum',
                       'mixedalphaspecial', 'upperalphaspecialnum', 'mixedalphaspecialnum'],
        'regex': ['^[a-z]+$', '^[A-Z]+$', '^[0-9]+$', '^[\p{posix_punct}]+$', '^[a-z0-9]+$', '^[A-Z0-9]+$',
                  '^[a-zA-Z]+$', '^[a-z\p{posix_punct}]+$', '^[A-Z\p{posix_punct}]+$', '^[\p{posix_punct}0-9]+$',
                  '^[a-zA-Z0-9]+$', '^[a-z\p{posix_punct}0-9]+$', '^[A-Za-z\p{posix_punct}]+$',
                  '^[A-Z\p{posix_punct}0-9]+$', '^[A-Za-z\p{posix_punct}0-9]+$'],
        'count': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}

    resultsTable = {
        'username': [],
        'hash': [],
        'password': [],
        'length': [],
        'complexity': []
    }

    compTable = pd.DataFrame(complexityTable)
    resTable = pd.DataFrame(resultsTable)

    def countLength(password):
        length = len(password)
        return length

    passFile = open(analyzeFile, "r")

    for line in passFile:
        temp = line.split(':')
        for index, row in compTable.iterrows():
            if (re2.match(compTable.at[index, 'regex'], temp[2].rstrip('\n'))):
                compTable.at[index, 'count'] = compTable.at[index, 'count'] + 1
                line = pd.DataFrame({'username': [temp[0].rstrip('\n')], 'hash': [temp[1].rstrip('\n')], 'password': [temp[2].rstrip('\n')],
                                     'length': [int(countLength(temp[2].rstrip('\n')))],
                                     'complexity': [compTable.at[index, 'complexity']]})
                resTable = resTable.append(line)
                break

    resTable[['username', 'hash', 'password', 'length', 'complexity']].to_csv(outFile, index=False)

    passFile.close()

def build_hc_post_command(mode_num, combined_file, hash_dir, hash_file):
    now = datetime.datetime.now()
    hash_loc = hash_dir + "/" + hash_file
    hc_results_file = hash_dir + "/" + "temp-" + hash_file + now.strftime("%Y-%m-%d-%H-%M-%S") + ".txt"
    hc_cmd = f'hashcat -m {mode_num} --show --username {hash_loc} --potfile-path={combined_file} -o {hc_results_file}'
    csv_name = hash_dir + "/" + "hashcat-" + hash_file + "-" + now.strftime("%Y-%m-%d-%H-%M-%S") + ".csv"
    return csv_name, hc_results_file, hc_cmd

def build_hc_command(wordlist_file, rule, mode_num, pot_file, hash_dir, hash_file):
    now = datetime.datetime.now()
    pot_loc = hash_dir + "/" + pot_file + "-" + re.sub('\.txt', '', wordlist_file) + "-" + re.sub('\.rule', '', rule) + "-" + now.strftime("%Y-%m-%d-%H-%M-%S") + ".pot"
    hash_loc = hash_dir + "/" + hash_file
    hc_cmd = f'hashcat {hash_loc} -m {mode_num} --potfile-path={pot_loc} -r {rules_path+rule} {wordlist_path+wordlist_file}'

    pot_file_list.append(pot_loc)

    lwfile = re.sub('\.txt', '', wordlist_file)
    lrule = re.sub('\.rule', '', rule)
    tempLogName = f'{lwfile}-{lrule}'
    log_name = "hashcat-" + tempLogName + "-" + now.strftime("%Y-%m-%d-%H-%M-%S") + ".log"

    return log_name, hc_cmd

def countLength(password):
    length = len(password)
    return length

def unique(list1):
    x = np.array(list1)
    return np.unique(x)

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "h:m:d:p:f:", ["mode=", "hash_dir=", "pot=", "hash_file="])
    except getopt.GetoptError:
        print('hashcat-proj.py -m <mode> -d <hash_dir> -p <pot> -f <hash_file>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('hashcat.py -m <mode> -d <hash_dir>')
            sys.exit()
        elif opt in ("-m", "--mode"):
            hc_mode = arg
        elif opt in ("-d", "--hash_dir"):
            hash_dir = arg
        elif opt in ("-p", "--pot"):
            pot_file = arg
        elif opt in ("-f", "--hash_file"):
            hash_file = arg

    complexityTable = {
        'complexity': ['loweralpha', 'upperalpha', 'numeric', 'special', 'loweralphanum', 'upperalphanum', 'mixedalpha',
                       'loweralphaspecial', 'upperalphaspecial', 'specialnum', 'mixedalphanum', 'loweralphaspecialnum',
                       'mixedalphaspecial', 'upperalphaspecialnum', 'mixedalphaspecialnum'],
        'regex': ['^[a-z]+$', '^[A-Z]+$', '^[0-9]+$', '^[\p{posix_punct}]+$', '^[a-z0-9]+$', '^[A-Z0-9]+$',
                  '^[a-zA-Z]+$', '^[a-z\p{posix_punct}]+$', '^[A-Z\p{posix_punct}]+$', '^[\p{posix_punct}0-9]+$',
                  '^[a-zA-Z0-9]+$', '^[a-z\p{posix_punct}0-9]+$', '^[A-Za-z\p{posix_punct}]+$',
                  '^[A-Z\p{posix_punct}0-9]+$', '^[A-Za-z\p{posix_punct}0-9]+$'],
        'count': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}

    compTable = pd.DataFrame(complexityTable)

    now = datetime.datetime.now()
    hashcat_session_file = hash_dir + "/" + "hashcat_session_log_" + now.strftime("%Y_%m_%d_%H_%M_%S") + ".json"

    pot_file_list = []

    for wordlist_file in wordlist_files:
        for rule in rule_files:
            resultsTable = {
                'length': [],
                'complexity': []
            }

            resTable = pd.DataFrame(resultsTable)

            logfile_name, hc_cmd = build_hc_command(wordlist_file, rule, hc_mode, pot_file, hash_dir, hash_file)

            hc_split = hc_cmd.split(" ", 8)
            logfile = hash_dir + "/" + logfile_name

            start_time = int(time.time() * 1000)

            process = subprocess.Popen(hc_split, stdout=subprocess.PIPE)
            with open(logfile, 'wb') as f:
                for c in iter(lambda: process.stdout.read(1), b''):  # replace '' with b'' for Python 3
                    sys.stdout.write(c.decode('utf-8', 'ignore'))
                    f.write(c)

            end_time = int(time.time() * 1000)

            pot_file_read = re.sub('--potfile-path=', '', hc_split[4])

            pot_file_list.append(hc_split[4])

            with open(str(pot_file_read), 'r') as fp:
                num_lines = len(fp.readlines())

            passFile = open(str(pot_file_read), "r")

            for line in passFile:

                temp = line.split(':')

                for index, row in compTable.iterrows():
                    if re2.match(compTable.at[index, 'regex'], temp[1].rstrip('\n')):
                        compTable.at[index, 'count'] = compTable.at[index, 'count'] + 1
                        line = pd.DataFrame({'password': [temp[1].rstrip('\n')],
                                             'length': [round(int(countLength(temp[1].rstrip('\n'))))],
                                             'complexity': [compTable.at[index, 'complexity']]})
                        resTable = resTable.append(line)
                        df_solution = resTable.groupby(['length', 'complexity']).size().reset_index().rename(
                            columns={0: 'complexity_count'}).to_json(orient="records")
                        break

            passFile.close()

            log_entry_temp = {"start_time": start_time, "end_time": end_time, "wordlist": wordlist_file, "rule": rule, "hashes-cracked": num_lines}

            log_entry_temp["results"] = eval(df_solution)

            with open(hashcat_session_file, 'a') as hs:
                hs.write(json.dumps(log_entry_temp))

    temp_hash_list = []

    for pot in pot_file_list:
        temp = re.sub('--potfile-path=', '', pot)

        with open(temp, 'r') as infile:
            #temp_hash_list = [line.strip() for line in infile]
            lines = infile.readlines()
            for line in lines:
                temp_hash_list.append(line.strip())

    unique_hash_list = unique(temp_hash_list)

    combind_file = hash_dir + "/" + "hashcat_combind" + now.strftime("%Y_%m_%d_%H_%M_%S") + ".txt"

    results_file = open(combind_file, "w")

    for item in unique_hash_list:
        results_file.write(item + "\n")

    csv_name, hc_results_file, hc_cmd = build_hc_post_command(hc_mode, combind_file, hash_dir, hash_file)

    hc_split = hc_cmd.split(" ", 8)

    subprocess.run(hc_split)

    create_csv_all_data(hc_results_file, csv_name)

    sys.exit()


if __name__ == '__main__':
    main(sys.argv[1:])
