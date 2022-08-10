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
MAILCHIMP_API_KEY = os.getenv('MAILCHIMP_API_KEY')
MAILCHIMP_SERVER_PREFIX = os.getenv('MAILCHIMP_SERVER_PREFIX')
MAILCHIMP_TS_LIST_ID = os.getenv('MAILCHIMP_TS_LIST_ID')
CEREMONY_START_DATE = os.getenv('CEREMONY_START_DATE')

email = "hiwz2ster@gmail.com"
token = "test_token"
emails = ["hiwz2ster@gmail.com"]
cohort = 1
cohort_tag = "ts_cohort_" + str(cohort)
template_id = 10276251

start_date = datetime.datetime.strptime(
    CEREMONY_START_DATE, "%Y-%m-%d %H:%M:%S")
cohort_datetime = start_date + datetime.timedelta(days=cohort)
cohort_date_str = cohort_datetime.strftime("%Y-%m-%d")

print(start_date)
print(cohort_datetime)

try:
    client = MailchimpMarketing.Client()
    client.set_config({
        "api_key": MAILCHIMP_API_KEY,
        "server": MAILCHIMP_SERVER_PREFIX
    })
# Update merge tags/fields with the latest ceremony_token and cohort_start_date
    response_set_list_member = client.lists.set_list_member(MAILCHIMP_TS_LIST_ID, email, {
        "email_address": email, "status_if_new": "unsubscribed", "merge_fields": {"TSTOKEN": token, "TSCOHORT": cohort_date_str}
    })
    # response = client.lists.update_list_member_tags(
    #     MAILCHIMP_TS_LIST_ID, email, {"tags": [{"name": cohort_tag, "status": "active"}]})
    # Add cohort list to specific cohort-based segment
    response_create_segment = client.lists.create_segment(
        MAILCHIMP_TS_LIST_ID, {"name": cohort_tag, "static_segment": emails})
    print(response_create_segment)
    # Create campaign using existing template_id and send to specific cohort
    response_create_campaign = client.campaigns.create(
        {"type": "regular",
         "recipients": {
             "segment_opts": {
                 "saved_segment_id": response_create_segment['id']
             },
             "list_id": MAILCHIMP_TS_LIST_ID
         },
            "settings": {
             "subject_line": "subject_line",
             "preview_text": "preview_text",
             "title": "title",
             "from_name": "from_name",
             "reply_to": "newsletter@anoma.network",
             "template_id": template_id
         }})
    print(response_create_campaign)
    # Schedule previous campaign with corresponding datetime 
    response_schedule_campaign = client.campaigns.schedule(response_create_campaign['id'], {
        "schedule_time": cohort_datetime.isoformat()})
    print(response_schedule_campaign)

except ApiClientError as error:
    print("Error: {}".format(error.text))
