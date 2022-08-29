import string
from tracemalloc import start
from mailchimp_marketing.api_client import ApiClientError
import mailchimp_marketing as MailchimpMarketing
import json
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()
# Mailchimp API config
MAILCHIMP_API_KEY = os.getenv('MAILCHIMP_API_KEY')
MAILCHIMP_SERVER_PREFIX = os.getenv('MAILCHIMP_SERVER_PREFIX')
# Ceremony Parameters
# Add the list id found in mailchimp
MAILCHIMP_TS_LIST_ID = os.getenv('MAILCHIMP_TS_LIST_ID')
CEREMONY_START_TIMESTAMP = os.getenv('CEREMONY_START_TIMESTAMP')
# Add the start date in the following example format: "2022-09-30 12:00:00"
CEREMONY_ANNOUNCEMENT_DATE = os.getenv('CEREMONY_ANNOUNCEMENT_DATE')
NUMBER_OF_COHORTS = int(os.getenv('NUMBER_OF_COHORTS'))
NAMADA_TOKENS_PATH = os.getenv('NAMADA_TOKENS_PATH')
ceremony_start_date = datetime.fromtimestamp(CEREMONY_START_TIMESTAMP)
ceremony_announcement_date = datetime.strptime(
    CEREMONY_ANNOUNCEMENT_DATE, "%Y-%m-%d %H:%M:%S")


campaign_settings_file = open('mc_campaign_settings.json')
campaign_settings = json.load(campaign_settings_file)


def load_emails_and_tokens():
    emails = []
    tokens = []
    for cohort in range(NUMBER_OF_COHORTS):
        with open("{}/namada_cohort_{}.json".format(NAMADA_TOKENS_PATH, cohort)) as f:
            cohort_file = json.load(f)
            emails_cohort = []
            tokens_cohort = []
            for i in range(len(cohort_file)):
                email = cohort_file[i][0]
                emails_cohort.append(email)
                token = cohort_file[i][1]
                tokens_cohort.append(token)
        emails.append(emails_cohort)
        tokens.append(tokens_cohort)
    return (emails, tokens)


(emails, tokens) = load_emails_and_tokens()


def cohort_tag(cohort): return "ts_cohort_" + str(cohort)


def calculate_cohort_datetime(ceremony_start_date: datetime, cohort: int):
    return ceremony_start_date + datetime.timedelta(days=cohort)


def calculate_cohort_reminder_1_week(ceremony_start_date: datetime, cohort: int):
    return calculate_cohort_datetime(ceremony_start_date, cohort) - datetime.timedelta(days=7)


def calculate_cohort_reminder_1_day(ceremony_start_date: datetime, cohort: int):
    return calculate_cohort_datetime(ceremony_start_date, cohort) - datetime.timedelta(days=1)


def calculate_cohort_reminder_1_hour(ceremony_start_date: datetime, cohort: int):
    return calculate_cohort_datetime(ceremony_start_date, cohort) - datetime.timedelta(hours=1)


def update_member_merge_tags(email: string, token: string, cohort_datetime: datetime, cohort: int):
    # Update member list's merge tags: TS_TOKEN, TS_CO_DATE
    try:
        client = MailchimpMarketing.Client()
        client.set_config({
            "api_key": MAILCHIMP_API_KEY,
            "server": MAILCHIMP_SERVER_PREFIX
        })
        cohort_date_str = cohort_datetime.strftime("%Y-%m-%d")
        response = client.lists.set_list_member(MAILCHIMP_TS_LIST_ID, email, {
            "email_address": email, "status_if_new": "subscribed", "merge_fields": {"TS_TOKEN": token, "TS_CO_DATE": cohort_date_str, "TS_COHORT": cohort}
        })
        print(response)

    except ApiClientError as error:
        print("Error: {}".format(error.text))


def create_segment(cohort_tag, emails):
    # Create segment/tag for specific cohort
    try:
        client = MailchimpMarketing.Client()
        client.set_config({
            "api_key": MAILCHIMP_API_KEY,
            "server": MAILCHIMP_SERVER_PREFIX
        })
        # Create segment from cohort email list
        response = client.lists.create_segment(
            MAILCHIMP_TS_LIST_ID, {"name": cohort_tag, "static_segment": emails})

        return response['id']

    except ApiClientError as error:
        print("Error: {}".format(error.text))


def create_and_load_segment_ids(emails):
    segment_ids = []
    for cohort in range(NUMBER_OF_COHORTS):
        segment_id = create_segment(cohort_tag(cohort), emails[cohort])
        segment_ids.append(segment_id)

    return segment_ids


segment_ids = create_and_load_segment_ids(emails)


def create_campaign(campaign_settings, cohort_segment_id):
    # Create new campaign for specific cohort segment id
    try:
        client = MailchimpMarketing.Client()
        client.set_config({
            "api_key": MAILCHIMP_API_KEY,
            "server": MAILCHIMP_SERVER_PREFIX
        })

        response = client.campaigns.create(
            {"type": "regular",
             "recipients": {
                 "segment_opts": {
                     "saved_segment_id": cohort_segment_id
                 },
                 "list_id": MAILCHIMP_TS_LIST_ID
             },
                "settings": campaign_settings
             })

        return response['id']

    except ApiClientError as error:
        print("Error: {}".format(error.text))


def schedule_campaign(campaign_id, cohort_datetime):
    try:
        client = MailchimpMarketing.Client()
        client.set_config({
            "api_key": MAILCHIMP_API_KEY,
            "server": MAILCHIMP_SERVER_PREFIX
        })

        response = client.campaigns.schedule(campaign_id, {
            "schedule_time": cohort_datetime.isoformat()})

        print(response)

    except ApiClientError as error:
        print("Error: {}".format(error.text))


def schedule_campaign_for_all_cohorts(calculate_cohort_datetime_function, datetime, campaign_settings, segment_ids):
    for cohort in range(NUMBER_OF_COHORTS):
        cohort_datetime = calculate_cohort_datetime_function(
            datetime, cohort)
        campaign_id = create_campaign(campaign_settings, segment_ids[cohort])
        schedule_campaign(campaign_id, cohort_datetime)

# Send "Spot is secured" email to all cohorts


def announce_ceremony(datetime, campaign_settings, segment_ids):
    for cohort in range(NUMBER_OF_COHORTS):
        campaign_id = create_campaign(campaign_settings, segment_ids[cohort])
        schedule_campaign(campaign_id, datetime)


# Spot secured
announce_ceremony(ceremony_announcement_date,
                  campaign_settings['spot_secured'], segment_ids)
# # REMINDER: 1 week
schedule_campaign_for_all_cohorts(
    calculate_cohort_reminder_1_week, ceremony_start_date, campaign_settings['reminder_1_week'], segment_ids)
# REMINDER: 1 hour
schedule_campaign_for_all_cohorts(
    calculate_cohort_reminder_1_hour, ceremony_start_date, campaign_settings['reminder_1_hour'], segment_ids)
# REMINDER: 1 day
schedule_campaign_for_all_cohorts(
    calculate_cohort_reminder_1_day, ceremony_start_date, campaign_settings['reminder_1_day'], segment_ids)
# Launch email
schedule_campaign_for_all_cohorts(
    calculate_cohort_datetime, ceremony_start_date, campaign_settings['cohort_live'], segment_ids)
