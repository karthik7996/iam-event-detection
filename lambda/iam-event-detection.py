import logging
import json
import os
import boto3
import urllib3

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

slack_url = os.environ['slack_url']
teams_url = os.environ['teams_url']

def lambda_handler(event, context):
    print("@@@@@@@@@@@@@")
    print(event)
    eventname = event['detail']['eventName']
    print(eventname)
    if eventname=="CreatePolicy":
        region = event['region']
        accountId = event['detail']['userIdentity']['accountId']
        policyname = event['detail']['responseElements']['policy']['policyName']
        userName = ''.join(event['detail']['userIdentity']['principalId'].split(':')[-1])
        message = "IAM Event detection. \n" "Incident: " + eventname + "\n"  + "Account: " + accountId +  "\n" + 'Region: ' + str(region)+ "\n"+ 'Policyname: ' + policyname + '\n' + "Username: " + userName
        post_to_slack(message)
    elif eventname == "DeletePolicy":
        region = event['region']
        accountId = event['detail']['userIdentity']['accountId']
        policyname = ''.join(event['detail']['requestParameters']['policyArn'].split('/')[-1])
        userName = ''.join(event['detail']['userIdentity']['principalId'].split(':')[-1])
        message = "IAM Event detection. \n" "Incident: " + eventname + "\n"  + "Account: " + accountId +  "\n" + 'Region: ' + str(region)+ "\n"+ 'Policyname: ' + str(policyname) + "\n" + "Username: " + userName
        post_to_slack(message)
    elif eventname=="CreateRole":
        region = event['region']
        accountId = event['detail']['userIdentity']['accountId']
        policyname = ''.join(event['detail']['requestParameters']['roleName'].split('/')[-1])
        userName = ''.join(event['detail']['userIdentity']['principalId'].split(':')[-1])
        message = "IAM Event detection. \n" "Incident: " + eventname + "\n"  + "Account: " + accountId +  "\n" + 'Region: ' + str(region)+ "\n"+ 'Rolename: ' + str(policyname) + "\n" + "Username: " + userName
        post_to_slack(message)
    elif eventname=="DeleteRole":
        region = event['region']
        accountId = event['detail']['userIdentity']['accountId']
        policyname = ''.join(event['detail']['requestParameters']['roleName'].split('/')[-1])
        userName = ''.join(event['detail']['userIdentity']['principalId'].split(':')[-1])
        message = "IAM Event detection. \n" "Incident: " + eventname + "\n"  + "Account: " + accountId +  "\n" + 'Region: ' + str(region)+ "\n"+ 'Rolename: ' + str(policyname) + "\n" + "Username: " + userName
        post_to_slack(message)
    elif eventname=="CreateUser":
        region = event['region']
        accountId = event['detail']['userIdentity']['accountId']
        policyname = ''.join(event['detail']['requestParameters']['userName'].split('/')[-1])
        userName = ''.join(event['detail']['userIdentity']['principalId'].split(':')[-1])
        message = "IAM Event detection. \n" "Incident: " + eventname + "\n"  + "Account: " + accountId +  "\n" + 'Region: ' + str(region)+ "\n"+ 'Iamuser: ' + str(policyname) + "\n" + "Username: " + userName
        post_to_slack(message)
    elif eventname=="DeleteUser":
        region = event['region']
        accountId = event['detail']['userIdentity']['accountId']
        policyname = ''.join(event['detail']['requestParameters']['userName'].split('/')[-1])
        userName = ''.join(event['detail']['userIdentity']['principalId'].split(':')[-1])
        message = "IAM Event detection. \n" "Incident: " + eventname + "\n"  + "Account: " + accountId +  "\n" + 'Region: ' + str(region)+ "\n"+ 'Iamuser: ' + str(policyname) + "\n" + "Username: " + userName
        post_to_slack(message)
    elif eventname=="CreateGroup":
        region = event['region']
        accountId = event['detail']['userIdentity']['accountId']
        policyname = ''.join(event['detail']['requestParameters']['groupName'].split('/')[-1])
        userName = ''.join(event['detail']['userIdentity']['principalId'].split(':')[-1])
        message = "IAM Event detection. \n" "Incident: " + eventname + "\n"  + "Account: " + accountId +  "\n" + 'Region: ' + str(region)+ "\n"+ 'Groupname: ' + str(policyname) + "\n" + "Username: " + userName
        post_to_slack(message)
    elif eventname=="DeleteGroup":
        region = event['region']
        accountId = event['detail']['userIdentity']['accountId']
        policyname = ''.join(event['detail']['requestParameters']['groupName'].split('/')[-1])
        userName = ''.join(event['detail']['userIdentity']['principalId'].split(':')[-1])
        message = "IAM Event detection. \n" "Incident: " + eventname + "\n"  + "Account: " + accountId +  "\n" + 'Region: ' + str(region)+ "\n"+ 'Groupname: ' + str(policyname) + "\n" + "Username: " + userName
        post_to_slack(message)


def post_to_slack(message):
    webhook_url = slack_url
    #log.info(str(webhook_url))
    teams_webhook_url = teams_url
    #log.info(str(teams_webhook_url))
    slack_data = {'text': message}
    http = urllib3.PoolManager()
    headers={'Content-Type': 'application/json'}
    encoded_data = json.dumps(slack_data).encode('utf-8')
    response = http.request('POST',webhook_url,body=encoded_data,headers=headers)
    #log.info('response is :'+str(response))
    response1 = http.request('POST',teams_webhook_url,body=encoded_data,headers=headers)
    #log.info('response-1 is :'+str(response1))
    return True
    
def setup_logging():
    """
    Logging Function.
    Creates a global log object and sets its level.
    """
    global log
    log = logging.getLogger()
    log_levels = {'INFO': 20, 'WARNING': 30, 'ERROR': 40}

    if 'logging_level' in os.environ:
        log_level = os.environ['logging_level'].upper()
        if log_level in log_levels:
            log.setLevel(log_levels[log_level])
        else:
            log.setLevel(log_levels['ERROR'])
            log.error("The logging_level environment variable is not set to INFO, WARNING, or \
                    ERROR.  The log level is set to ERROR")
    else:
        log.setLevel(log_levels['ERROR'])
        log.warning('The logging_level environment variable is not set. The log level is set to \
                  ERROR')
        #log.info('Logging setup complete - set to log level ' + log_level)