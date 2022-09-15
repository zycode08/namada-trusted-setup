import json
import csv
from hashlib import blake2b
import math
import os
import shutil
from dotenv import load_dotenv

load_dotenv()

MUCH_RANDOM_SECRET = os.getenv('MUCH_RANDOM_SECRET')
EMAILS_LIST_PATH = os.getenv('EMAILS_LIST_PATH')
NAMADA_TOKENS_PATH = os.getenv('NAMADA_TOKENS_PATH')
TOKENS_FILE_PREFIX = os.getenv('TOKENS_FILE_PREFIX')

PARTICIPANTS_PER_COHORT = int(os.getenv('PARTICIPANTS_PER_COHORT'))

emails = []
tokens = []
secret = MUCH_RANDOM_SECRET

# Clean up tokens directory
if os.path.isdir(NAMADA_TOKENS_PATH):
    shutil.rmtree(NAMADA_TOKENS_PATH)

os.mkdir(NAMADA_TOKENS_PATH)

def generate_token(data):
    h = blake2b(digest_size=10)
    h.update(bytes(data, 'utf-8') + bytes(secret, 'utf-8'))
    return h.hexdigest()

# Get the latest email list from email marketing platform
with open(EMAILS_LIST_PATH, newline='') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        email = row[1]
        emails.append(email)
        # Generate unique token by hashing the email and a random secret: hash(email||secret)
        token = generate_token(email)
        tokens.append(token)

# Create a list of tuple [email, token]
zipped_emails_tokens = list(map(list, zip(emails, tokens)))
# Allocate emails into cohorts depending on the number of participants per cohort
number_of_cohorts = math.ceil(len(emails) / PARTICIPANTS_PER_COHORT)

print("# of participants: ", len(emails))
print("Participants per cohort: ", PARTICIPANTS_PER_COHORT)
print("# of cohorts: ", number_of_cohorts)

for cohort in range(number_of_cohorts):
    start = cohort * PARTICIPANTS_PER_COHORT
    end = (cohort + 1) * PARTICIPANTS_PER_COHORT
    # Generate json file containing all tokens for a cohort
    # This will be used by the coordinator 
    with open("{}/{}_{}.json".format(NAMADA_TOKENS_PATH, TOKENS_FILE_PREFIX, cohort), "w") as f:
        f.write(json.dumps(tokens[start:end]))
    # Generate json file containing the list of tuples [email, token] for a cohort
    # This will be used to configure Mailchimp
    with open("{}/{}_{}.json".format(NAMADA_TOKENS_PATH, "namada_cohort", cohort), "w") as f:
        f.write(json.dumps(zipped_emails_tokens[start:end]))

# This section generates json files containing a Free For All (FFA) token only
# This will be used after the cohorts are done, in this manner we open the ceremony to everyone interested that didn't have the chance to register in time to be included in a cohort
IS_FFA_ACTIVE = os.getenv('IS_FFA_ACTIVE')
if IS_FFA_ACTIVE:
    FFA_TOKEN_SECRET = os.getenv('FFA_TOKEN_SECRET') 
    FFA_COHORTS = os.getenv('FFA_COHORTS')

    ffa_token = []
    ffa_token.append(generate_token(FFA_TOKEN_SECRET))
    ffa_cohorts = number_of_cohorts + int(FFA_COHORTS)
    for cohort in range(number_of_cohorts, ffa_cohorts):
        with open("{}/{}_{}.json".format(NAMADA_TOKENS_PATH, TOKENS_FILE_PREFIX, cohort), "w") as f:
            f.write(json.dumps(ffa_token))
