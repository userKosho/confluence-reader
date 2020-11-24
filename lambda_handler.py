from bs4 import BeautifulSoup

import json
import atlassian_jwt
import requests
import os

# for slack request validation
import hashlib
import hmac


class SecretObject:
    confluence_token = ''
    atlassian_connect_json = {}
    confluence_shared_secret = ''
    confluence_user_account_id = ''
    # confluence client key is not used, not sure what it is used for
    confluence_client_key = ''
    confluence_base_url = ''

    slack_token = ''
    slack_signing_secret = ''
    slack_bot_oauth_token = '' # get from console


def get_secrets(env):
    secret_object = SecretObject()
    if env.env == 'local':
        with open('.local/secrets.json') as file:
            data = json.load(file)
            secret_object.confluence_token = data['confluence_token']
            secret_object.atlassian_connect_json = data['atlassian_connect_json']
            secret_object.confluence_shared_secret = data['confluence_shared_secret']
            secret_object.confluence_user_account_id = data['confluence_user_account_id']
            secret_object.confluence_client_key = data['confluence_client_key']
            secret_object.confluence_base_url = data['confluence_base_url']
            secret_object.slack_token = data['slack_token']
            secret_object.slack_signing_secret = data['slack_signing_secret']
            secret_object.slack_bot_oauth_token = data['slack_bot_oauth_token']
    else:
        # TODO use arn to get the secret
        pass
    return secret_object


class Env(): 
    env = ''
    confluence_space_key = ''
    confluence_page_title = ''
    secrets_arn = ''
    slack_url = ''


def load_env():
    env = Env()
    env.env = os.environ.get('ENV')
    print(env.env)
    if env.env == 'local':
        with open('.local/env.json', 'r') as file:
            data = json.load(file)
            env.confluence_space_key = data['confluence_space_key']
            env.confluence_page_title = data['confluence_page_title']
            env.secrets_arn = data['secrets_arn']
            env.slack_url = data['slack_url']
    elif env.env == 'dev':
        pass
        # load via the environment variables
    return env


# used as a lambda cache
SECRET_OBJECT = None
ENV = None


def health():
    pass


def health_all():
    pass


def update_secrets(env, secret_object, arn):
    global SECRET_OBJECT
    SECRET_OBJECT = secret_object
    if env.env == 'local':
        with open('.local/secrets.json', 'w') as outfile:
            json.dump(secret_object.__dict__, outfile)

    # TODO : update secrets manager with new values


def handle_slack_challenge_request(body, secret_object, env):
    secret_object.slack_token = body['token']
    challenge = body['challenge']
    update_secrets(env, secret_object, env.secrets_arn)
    return {
        "statusCode": 200,
        "body": challenge
    }


def handle_slack_mention_request(body, secret_object, env):
    """

    """
    abbreviation = parse_slack_activation(body['text'])
    raw_html = get_confluence_page(secret_object, env)
    print(f'raw html \n\n\n {raw_html}')
    soup_html = BeautifulSoup(raw_html, 'lxml')
    definition = get_definition(soup_html, abbreviation)
    print(f'definition: \n {definition}')
    return post_slack_message(definition, body['channel'], secret_object, env)
    # return {
    #     "statusCode": 201
    # }


def post_slack_message(messsage, channel, secret_object, env):
    url = env.slack_url
    header = {
        'Content-type': 'application/json',
        'Authorization': f'Bearer {secret_object.slack_bot_oauth_token}'
    }
    data = {
        # 'token': secret_object.slack_token,
        'channel': channel,
        'text': messsage
    }
    print(f'url {url}')
    print(f'data {data}')
    x = requests.post(url, json=data, headers=header)
    print(x.json())
    return x


def get_definition(soup_html, abbreviation):
    ab = soup_html.find('h2', text=abbreviation)
    definitons = [abbreviation]
    if ab:
        ab = ab.find_next_sibling()
        while ab and ab.name == 'p':
            formatted_string = format_confluence_to_slack(str(ab))
            definitons.append(formatted_string)
            ab = ab.find_next_sibling()
        definitons.append('ref: link to confluence')
        return '\n\n'.join(definitons)
    else:
        return None


def get_confluence_page(secret_object, env):
    shared_secret = secret_object.confluence_shared_secret
    key = secret_object.atlassian_connect_json['key']
    uri = f'/rest/api/content?spaceKey={env.confluence_space_key}&title={env.confluence_page_title}&expand=body.storage'
    token = atlassian_jwt.encode_token(
        'GET', uri, clientKey=key, sharedSecret=shared_secret)
    headers = {'Authorization': 'JWT {}'.format(token)}
    url = secret_object.confluence_base_url + uri

    test_get_response = requests.get(url, headers=headers)
    print(f'status form call {test_get_response.status_code }')
    # print(f'response form call {json.loads(test_get_response.content.decode("utf-8"))}')
    payload = json.loads(test_get_response.content)

    if test_get_response.status_code == 200:
        print(payload['results'][0]['body']['storage']['value'])
    return payload['results'][0]['body']['storage']['value']


def handle_slack_message_channel_request(body, arn):
    """
    Not Implemented
    Handles all read messages even if there is no mention
    """
    pass
# https://stackoverflow.com/questions/50484195/generate-hmac-sha256-in-python-3
# https://api.slack.com/authentication/verifying-requests-from-slack#sdk_support

# https://janikarhunen.fi/verify-slack-requests-in-aws-lambda-and-python
def validate_slack_request(event, secret_object):
    secret = bytes('40031918633c2eeda5464c814b727278', 'utf-8')
    data = event['body']
    headers = event['headers']
    signature = headers['X-Slack-Signature']
    time_stamp = headers['X-Slack-Request-Timestamp']
    message = f'v0:{time_stamp}:{data}'
    print(message)
    signature_computed = 'v0=' + hmac.new(
        key=secret,
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    print(f'computed sig {signature_computed}')
    print(f'given sig {signature}')
    if not hmac.compare_digest(signature, signature_computed):
        return False
    return True


def parse_slack_activation(message):
    """
    text message format: 
    @batman define g2g
    @batman what is FBI
    """
    list_of_words = message.split()
    try:
        abbreviation = list_of_words[list_of_words.index('define') + 1]
    except ValueError:
        pass
    else:
        return abbreviation.upper()
    try:
        abbreviation = list_of_words[list_of_words.index('what is') + 1]
    except ValueError:
        return None
    else:
        return abbreviation.upper()


def format_confluence_to_slack(message):
    message = message.replace('<strong>', '*')
    message = message.replace('</strong>', '*')
    message = message.replace('<br/>', '\n')
    message = message.replace('<p>', '')
    message = message.replace('</p>', '')
    return message


def handle_get_conflunce_app_descriptor(event, secret_object):
    return {
        "statusCode": 200,
        "body": json.dumps(secret_object.atlassian_connect_json)
    }


def handle_confluence_installed(event, secret_object, env):
    if validate_installed_request(event, secret_object):
        body = event['body']
        secret_object.confluence_shared_secret = body['sharedSecret']
        secret_object.confluence_user_account_id = event['queryStringParameters']
        secret_object.confluence_base_url = body['baseUrl']
        secret_object.confluence_client_key = body['clientKey']
        update_secrets(env, secret_object, env.secrets_arn)
        return {
            "statusCode": 200,
            "body": 'success'
        }
    else:
        return {
            "statusCode": 400,
            "body": 'validation of request failed'
        }


def validate_installed_request(event, secret_object):
    """
    this function validates if the app was already installed on confluence
    Since this is an internal app, we only allow a single confluence install
    """
    # TODO: actually validate event
    print(f'secret shared {secret_object.confluence_shared_secret}')
    if secret_object.confluence_shared_secret == '':
        return True
    else:
        return False


def route_call(event, secret_object, env):
    path = event['path']
    if '/confluence/atlassian-connect' in path:
        return handle_get_conflunce_app_descriptor(event, secret_object)
    elif '/confluence/installed' in path:
        return handle_confluence_installed(event, secret_object, env)
    elif '/slack' in path:
        return route_slack_call(event, secret_object, env)
    else:
        return {
            "statusCode": 400,
            "body": 'validation of request failed'
        }


def route_slack_call(event, secret_object, env):
    print('in route slack call')
    body = event['body']
    event_type = body['type']
    if event_type == 'url_verification':
        return handle_slack_challenge_request(body, secret_object, env)

    
    event_type = body['event']['type']
    print(validate_slack_request(event, secret_object))
    if event_type == 'app_mention':
        return handle_slack_mention_request(body['event'], secret_object, env)
    else:
        return {
            "statusCode": 404,
            "body": f'unhandled route type {event_type}'
        }


def handler(event, context):
    global ENV, SECRET_OBJECT
    print('handler called')
    if not ENV:
        ENV = load_env()
    if not SECRET_OBJECT:
        SECRET_OBJECT = get_secrets(ENV)
    print(f'{ENV.env}')
    print(f'{SECRET_OBJECT.confluence_token}')
    return route_call(event, SECRET_OBJECT, ENV)
