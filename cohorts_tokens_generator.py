import json
import csv
from hashlib import blake2b
import math
import os
from dotenv import load_dotenv

load_dotenv()
MUCH_RANDOM_SECRET = os.getenv('MUCH_RANDOM_SECRET')
EMAILS_LIST_PATH = os.getenv('EMAILS_LIST_PATH')

PARTICIPANTS_PER_COHORT = 1000

emails = []
tokens = []
secret = MUCH_RANDOM_SECRET

# Get the latest email list from email marketing platform
with open(EMAILS_LIST_PATH, newline='') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        emails.append(row[0])
        # Generate unique token by hashing the email and a random secret
        h = blake2b(digest_size=10)
        h.update(bytes(row[0], 'utf-8') + bytes(secret, 'utf-8'))
        tokens.append(h.hexdigest())

zipped_emails_tokens = list(map(list, zip(emails, tokens)))

number_of_cohorts = math.ceil(len(emails) / PARTICIPANTS_PER_COHORT)

for cohort in range(number_of_cohorts):
    with open("tokens_test/namada_tokens_cohort_{}.json".format(cohort), "w") as f:
        start = cohort * PARTICIPANTS_PER_COHORT
        end = (cohort + 1) * PARTICIPANTS_PER_COHORT
        f.write(json.dumps(tokens[start:end]))

    with open("tokens_test/namada_cohort_{}.json".format(cohort), "w") as f:
        start = cohort * PARTICIPANTS_PER_COHORT
        end = (cohort + 1) * PARTICIPANTS_PER_COHORT
        f.write(json.dumps(zipped_emails_tokens[start:end]))
