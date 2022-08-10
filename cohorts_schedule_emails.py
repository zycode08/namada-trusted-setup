from tracemalloc import start
from mailchimp_marketing.api_client import ApiClientError
import mailchimp_marketing as MailchimpMarketing
import json
import csv
from hashlib import blake2b
import math
import os
from dotenv import load_dotenv
import datetime

load_dotenv()
# Mailchimp API config
MAILCHIMP_API_KEY = os.getenv('MAILCHIMP_API_KEY')
MAILCHIMP_SERVER_PREFIX = os.getenv('MAILCHIMP_SERVER_PREFIX')
# Ceremony Parameters
MAILCHIMP_TS_LIST_ID = os.getenv('MAILCHIMP_TS_LIST_ID')
CEREMONY_START_DATE = os.getenv('CEREMONY_START_DATE')

ceremony_start_date = datetime.datetime.strptime(
    CEREMONY_START_DATE, "%Y-%m-%d %H:%M:%S")

campaign_settings = {
    "subject_line": "subject_line",
    "preview_text": "preview_text",
    "title": "title",
    "from_name": "from_name",
    "reply_to": "newsletter@anoma.network",
    "template_id": 10276251
}
# FIXME: testing purposes only, remove me
email = "hiwz2ster@gmail.com"
token = "test_token"
emails = ["hiwz2ster@gmail.com"]
cohort = 1
number_of_cohorts = 5


def cohort_tag(cohort): return "ts_cohort_" + str(cohort)


def calculate_cohort_datetime(ceremony_start_date, cohort):
    return ceremony_start_date + datetime.timedelta(days=cohort)

# Update member list's merge tags: TSTOKEN, TSCOHORT


def update_member_merge_tags(email, token, cohort_datetime):
    try:
        client = MailchimpMarketing.Client()
        client.set_config({
            "api_key": MAILCHIMP_API_KEY,
            "server": MAILCHIMP_SERVER_PREFIX
        })
        cohort_date_str = cohort_datetime.strftime("%Y-%m-%d")
        response = client.lists.set_list_member(MAILCHIMP_TS_LIST_ID, email, {
            "email_address": email, "status_if_new": "unsubscribed", "merge_fields": {"TSTOKEN": token, "TSCOHORT": cohort_date_str}
        })
        print(response)

    except ApiClientError as error:
        print("Error: {}".format(error.text))


def create_and_schedule_campaign(campaign_settings, emails, cohort_tag, cohort_datetime):
    try:
        client = MailchimpMarketing.Client()
        client.set_config({
            "api_key": MAILCHIMP_API_KEY,
            "server": MAILCHIMP_SERVER_PREFIX
        })
        # Create segment from cohort email list
        response_create_segment = client.lists.create_segment(
            MAILCHIMP_TS_LIST_ID, {"name": cohort_tag, "static_segment": emails})
        # Create campaign from template_id
        response_create_campaign = client.campaigns.create(
            {"type": "regular",
             "recipients": {
                 "segment_opts": {
                     "saved_segment_id": response_create_segment['id']
                 },
                 "list_id": MAILCHIMP_TS_LIST_ID
             },
                "settings": campaign_settings
             })
        print(response_create_campaign)
        # Schedule previous campaign with corresponding datetime
        response_schedule_campaign = client.campaigns.schedule(response_create_campaign['id'], {
            "schedule_time": cohort_datetime.isoformat()})
        print(response_schedule_campaign)

    except ApiClientError as error:
        print("Error: {}".format(error.text))


for cohort in range(number_of_cohorts):
    with open("tokens_test/namada_cohort_{}.json".format(cohort)) as f:
        cohort_file = json.load(f)
        cohort_datetime = calculate_cohort_datetime(
            ceremony_start_date, cohort)
        emails = []
        print(cohort_tag(cohort))
        for i in range(len(cohort_file)):
            email = cohort_file[i][0]
            emails.append(email)
            token = cohort_file[i][1]
            # update_member_merge_tags(email, token, cohort_datetime)
            print("update_member_merge_tags: ", email, token, cohort_datetime)
        print("create_and_schedule_campaign: ", campaign_settings, emails,
              cohort_tag(cohort), cohort_datetime)
