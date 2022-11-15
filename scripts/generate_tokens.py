import argparse
import csv
import json
import os
import secrets
import shutil
import base58
from datetime import datetime
from math import ceil
from typing import Dict, List, Tuple, Union

FFA_TOKEN_PREFIX="ffa"
PER_USER_TOKEN="put"


def load_json(path: str) -> Dict[str, Union[int, str]]:
    return json.load(open(path, "r"))


def load_emails(path: str) -> List[str]:
    return [row[0] for row in csv.reader(open(path, "r", newline=""))]


def format_timestamp_to_datetime(ts: int) -> str:
    return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


def setup_ceremony_output_folder(config: Dict[str, str]) -> Tuple[bool, Union[str, None]]:
    ceremony_start_time = config["ceremony_start_utc"]
    output_folder = "{}-ceremony".format(ceremony_start_time)

    if os.path.isdir(output_folder):
        answer = input("Folder {} already exist. Do you want to remove it? [y/n] ".format(output_folder))
        if answer == "y":
            shutil.rmtree(output_folder)
            os.mkdir("{}-ceremony".format(ceremony_start_time))
            os.mkdir("{}-ceremony/mailchimp".format(ceremony_start_time))
            os.mkdir("{}-ceremony/coordinator".format(ceremony_start_time))
            return True, output_folder
        else:
            print("You need to remove {} folder first".format(output_folder))
            return False, None
    else:
        os.mkdir("{}-ceremony".format(ceremony_start_time))
        os.mkdir("{}-ceremony/mailchimp".format(ceremony_start_time))
        os.mkdir("{}-ceremony/coordinator".format(ceremony_start_time))
        return True, output_folder


def generate_token(ceremony_start: int, cohort_index: int, cohort_duration: int, is_ffa: bool = False):
    if is_ffa:
        return FFA_TOKEN_PREFIX + "_" + secrets.token_hex(nbytes=16)
    
    cohort_start = ceremony_start + cohort_duration * cohort_index
    cohort_end = cohort_start + cohort_duration
    return PER_USER_TOKEN + "_" + base58.b58encode(json.dumps({
        "from": cohort_start,
        "to": cohort_end,
        "index": cohort_index + 1,
        "id": secrets.token_hex(nbytes=12)
    }).encode()).decode()


def dump_mailchimp_data(output_folder: str, format: str, cohort_index: int, data: List[List[str]]):
    filename = format.format(cohort_index)
    with open("{}/mailchimp/{}.json".format(output_folder, filename), "w") as f:
        f.write(json.dumps(data))


def dump_coordinator_data(output_folder: str, format: str, cohort_index: int, data: List[str]):
    filename = format.format(cohort_index)
    with open("{}/coordinator/{}.json".format(output_folder, filename), "w") as f:
        f.write(json.dumps(data))


def create_coordinate_token_zip(output_folder: str):
    output_folder = "{}/coordinator".format(output_folder)
    shutil.make_archive(output_folder, 'zip', output_folder)


def main(args: argparse.Namespace):
    config = load_json(args.config_path)
    emails = load_emails(args.emails_path)

    success, output_folder = setup_ceremony_output_folder(config)
    if not success:
        exit(0)

    max_cohort_participant = config['participant_per_cohort']
    ceremony_start = config["ceremony_start_utc"]
    cohort_duration = config["cohort_duration"]
    total_participant = len(emails)
    total_cohorts = ceil(total_participant / config['participant_per_cohort'])
    ffa_total_cohorts = config["ffa_cohorts"]
    ceremony_end = int(ceremony_start + cohort_duration * total_cohorts)

    print("Ceremony start: {}".format(format_timestamp_to_datetime(ceremony_start)))
    print("Ceremony end: {}".format(format_timestamp_to_datetime(ceremony_end)))
    print("Total participants: {}".format(total_participant))
    print("Cohort duration: {} minutes".format(cohort_duration // 60))
    print("Total cohorts: {}".format(total_cohorts))

    answer = input("Is this correct? [y/n] ")
    if answer != "y":
        exit(0)

    cohort_filename_format = config["cohort_filename_format"]
    mailchimp_filename_format = config["mailchimp_filename_format"]

    for cohort_index in range(total_cohorts):
        print("Cohort: {}".format(cohort_index + 1))

        emails_start_index = cohort_index * max_cohort_participant
        emails_end_index = min(len(emails), emails_start_index + max_cohort_participant)

        mailchimp_cohort_data = []
        coordinator_cohort_data = []
        for email_index in range(emails_start_index, emails_end_index):
            print(" - {}".format(emails[email_index]))

            token = generate_token(ceremony_start, cohort_index, cohort_duration)
            mailchimp_cohort_data.append([emails[email_index], token])
            coordinator_cohort_data.append(token)

        dump_mailchimp_data(output_folder, mailchimp_filename_format, cohort_index + 1, mailchimp_cohort_data)
        dump_coordinator_data(output_folder, cohort_filename_format, cohort_index + 1, coordinator_cohort_data)

    ffa_token = generate_token(None, None, None, True)

    for ffa_cohort_index in range(ffa_total_cohorts):
        coordinator_cohort_data = []
        for _ in range(max_cohort_participant):
            coordinator_cohort_data.append(ffa_token)
        
        dump_coordinator_data(output_folder, cohort_filename_format, total_cohorts + ffa_cohort_index + 1, coordinator_cohort_data)

    dump_coordinator_data(output_folder, cohort_filename_format,  total_cohorts + ffa_total_cohorts + 1, [[] for _ in range(max_cohort_participant)])

    create_coordinate_token_zip(output_folder)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='TSToken', description='Generate trusted setup cohort tokens')
    parser.add_argument('--emails-path', action='store', type=str, default="emails.csv")
    parser.add_argument('--config-path', action='store', type=str, default="config.json")

    args = parser.parse_args()

    main(args)