import json
import csv
from hashlib import blake2b
import math
import os
from dotenv import load_dotenv

load_dotenv()
MUCH_RANDOM_SECRET = os.getenv('MUCH_RANDOM_SECRET')
EMAILS_LIST_PATH = os.getenv('EMAILS_LIST_PATH')

PARTICIPANTS_PER_COHORT = os.getenv('PARTICIPANTS_PER_COHORT')

emails = []
tokens = []
secret = MUCH_RANDOM_SECRET

# Get the latest email list from email marketing platform
with open(EMAILS_LIST_PATH, newline='') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        email = row[0]
        emails.append(email)
        # Generate unique token by hashing the email and a random secret: hash(email||secret)
        h = blake2b(digest_size=10)
        h.update(bytes(email, 'utf-8') + bytes(secret, 'utf-8'))
        tokens.append(h.hexdigest())

# Create a list of tuple [email, token]
zipped_emails_tokens = list(map(list, zip(emails, tokens)))

number_of_cohorts = math.ceil(len(emails) / PARTICIPANTS_PER_COHORT)

for cohort in range(number_of_cohorts):
    # Generate json file containing all tokens for a cohort
    with open("tokens_test/namada_tokens_cohort_{}.json".format(cohort), "w") as f:
        start = cohort * PARTICIPANTS_PER_COHORT
        end = (cohort + 1) * PARTICIPANTS_PER_COHORT
        f.write(json.dumps(tokens[start:end]))

    # Generate json file containing the list of tuples [email, token] for a cohort
    with open("tokens_test/namada_cohort_{}.json".format(cohort), "w") as f:
        start = cohort * PARTICIPANTS_PER_COHORT
        end = (cohort + 1) * PARTICIPANTS_PER_COHORT
        f.write(json.dumps(zipped_emails_tokens[start:end]))
