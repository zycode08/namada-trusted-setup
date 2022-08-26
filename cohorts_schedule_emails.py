import string
from tracemalloc import start
from mailchimp_marketing.api_client import ApiClientError
import mailchimp_marketing as MailchimpMarketing
import json
import os
from dotenv import load_dotenv
import datetime

load_dotenv()
# Mailchimp API config
MAILCHIMP_API_KEY = os.getenv('MAILCHIMP_API_KEY')
MAILCHIMP_SERVER_PREFIX = os.getenv('MAILCHIMP_SERVER_PREFIX')
# Ceremony Parameters
# Add the list id found in mailchimp
MAILCHIMP_TS_LIST_ID = os.getenv('MAILCHIMP_TS_LIST_ID')
# Add the start date in the following example format: "2022-09-30 12:00:00"
CEREMONY_START_DATE = os.getenv('CEREMONY_START_DATE')
NUMBER_OF_COHORTS = int(os.getenv('NUMBER_OF_COHORTS'))
TOKENS_PATH = os.getenv('TOKENS_PATH')
ceremony_start_date = datetime.datetime.strptime(
    CEREMONY_START_DATE, "%Y-%m-%d %H:%M:%S")

campaign_settings_file = open('mc_campaign_settings.json')
campaign_settings = json.load(campaign_settings_file)


def cohort_tag(cohort): return "ts_cohort_" + str(cohort)


def calculate_cohort_datetime(ceremony_start_date: datetime, cohort: int):
    return ceremony_start_date + datetime.timedelta(days=cohort)


def calculate_cohort_reminder_1_week(ceremony_start_date: datetime, cohort: int):
    return calculate_cohort_datetime(ceremony_start_date, cohort) - datetime.timedelta(days=7)


def calculate_cohort_reminder_1_day(ceremony_start_date: datetime, cohort: int):
    return calculate_cohort_datetime(ceremony_start_date, cohort) - datetime.timedelta(days=1)


def calculate_cohort_reminder_1_hour(ceremony_start_date: datetime, cohort: int):
    return calculate_cohort_datetime(ceremony_start_date, cohort) - datetime.timedelta(hours=1)

# Update member list's merge tags: TS_TOKEN, TS_CO_DATE


def update_member_merge_tags(email: string, token: string, cohort_datetime: datetime):
    try:
        client = MailchimpMarketing.Client()
        client.set_config({
            "api_key": MAILCHIMP_API_KEY,
            "server": MAILCHIMP_SERVER_PREFIX
        })
        cohort_date_str = cohort_datetime.strftime("%Y-%m-%d")
        response = client.lists.set_list_member(MAILCHIMP_TS_LIST_ID, email, {
            "email_address": email, "status_if_new": "subscribed", "merge_fields": {"TS_TOKEN": token, "TS_CO_DATE": cohort_date_str}
        })
        print(response)

    except ApiClientError as error:
        print("Error: {}".format(error.text))

# Create and schedule a campaign


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


def schedule_campaign_for_cohorts(calculate_cohort_datetime_function, campaign_settings):
    for cohort in range(NUMBER_OF_COHORTS):
        with open("{}/namada_cohort_{}.json".format(TOKENS_PATH, cohort)) as f:
            cohort_file = json.load(f)
            cohort_datetime = calculate_cohort_datetime_function(
                ceremony_start_date, cohort)
            emails = []
            print(cohort_tag(cohort))
            for i in range(len(cohort_file)):
                email = cohort_file[i][0]
                emails.append(email)
                token = cohort_file[i][1]
                # update_member_merge_tags(email, token, cohort_datetime)
                print("update_member_merge_tags: ",
                      email, token, cohort_datetime)
            # create_and_schedule_campaign(
            #     campaign_settings, emails, cohort_tag(cohort), cohort_datetime)
            print("create_and_schedule_campaign: ", campaign_settings, emails,
                  cohort_tag(cohort), cohort_datetime)


# Spot secured
schedule_campaign_for_cohorts(
    calculate_cohort_reminder_1_week, campaign_settings['spot_secured'])
# REMINDER: 1 week
schedule_campaign_for_cohorts(
    calculate_cohort_reminder_1_week, campaign_settings['reminder_1_week'])
# REMINDER: 1 hour
schedule_campaign_for_cohorts(
    calculate_cohort_reminder_1_hour, campaign_settings['reminder_1_hour'])
# REMINDER: 1 day
schedule_campaign_for_cohorts(
    calculate_cohort_reminder_1_day, campaign_settings['reminder_1_day'])
# Launch email
schedule_campaign_for_cohorts(
    calculate_cohort_datetime, campaign_settings['cohort_live'])
