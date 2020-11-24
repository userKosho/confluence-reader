from typing import Any, Dict, Optional
from fastapi import FastAPI, Header
from pydantic import BaseModel
from bs4 import BeautifulSoup

import json
import atlassian_jwt
import requests


class Item(BaseModel):
    key: Optional[str] = None
    clientKey: Optional[str] = None
    sharedSecret: Optional[str] = None
    serverVersion: Optional[str] = None
    pluginsVersion: Optional[str] = None
    baseUrl: Optional[str] = None
    displayUrl: Optional[str] = None
    displayUrlServicedeskHelpCenter: Optional[str] = None
    productType: Optional[str] = None
    description: Optional[str] = None
    serviceEntitlementNumber: Optional[str] = None
    eventType: Optional[str] = None


class SlackChallenge(BaseModel):
    token: Optional[str] = None
    challenge: Optional[str] = None
    type: Optional[str] = None


app = FastAPI()

temp_item = Item()


# @app.api_route("/{full_path:path}")
# async def catch_all(full_path, challenge: Dict[Any, Any]):
#     print(f'aaaaaaaaa{full_path}')
#     context = None
#     # event = {
#     #     "path": f"{full_path}",
#     #     "httpMethod": "GET",
#     #     "body": None,
#     # }
#     # import lambda_handler
#     # return lambda_handler.handler(event, None)
#     return {"message": "Hello World"}


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/confluence/atlassian-connect")
async def app_descriptor():
    event = {
        "path": "/confluence/atlassian-connect",
        "httpMethod": "GET",
        "body": None,
    }
    import lambda_handler
    response = lambda_handler.handler(event, None)
    print(response)
    return json.loads(response['body'])

    # with open('atlassian-connect.json') as file:
    #     payload = json.load(file)
    # print('get installed called')
    # return payload

# @app.get("/installed")
# async def get_installed():
#     print('***************get installed called ************************')
#     return {"user_id": "the current user"}

# @app.post("/installed")
# async def post_installed(item: Item):
#     # print(f'user_account_id {user_account_id}')


#     print(f' ******************* \n received post obje {item} \n *******************************')
#     return True

@app.post("/confluence/installed")
async def post_installed(user_account_id, item: Item):
    global temp_item
    temp_item = item
    print(f'user_account_id {user_account_id}')

    print(
        f' ******************* \n received post objet {item} \n *******************************')
    event = {
        "path": "/confluence/installed",
        "queryStringParameters": f"{user_account_id}",
        "httpMethod": "POST",
        "body": item.dict(),
    }
    import lambda_handler
    response = lambda_handler.handler(event, None)
    print(response)
    return response['body']


@app.get("/confluence")
async def confluence():

    token = atlassian_jwt.encode_token('GET', '/rest/api/content?spaceKey=DEV&title=Acronyms&expand=body.storage', clientKey='',
                                       sharedSecret='')
    headers = {'Authorization': 'JWT {}'.format(token)}
    url = 'https://devkosho.atlassian.net/wiki/rest/api/content?spaceKey=DEV&title=Acronyms&expand=body.storage'

    test_get_response = requests.get(url, headers=headers)
    print(f'status form call {test_get_response.status_code }')
    # print(f'response form call {json.loads(test_get_response.content.decode("utf-8"))}')
    payload = json.loads(test_get_response.content)

    if test_get_response.status_code == 200:
        print(payload['results'][0]['body']['storage']['value'])
    return json.loads(test_get_response.content)


@app.post("/slack")
async def slack_event(challenge: Dict[Any, Any], X_Slack_Signature: Optional[str] = Header(None), X_Slack_Request_Timestamp: Optional[str] = Header(None)):
    # check if this is a first time challenge request

    print(f'payload: \n {challenge}')

    event = {
        "path": "/slack",
        "httpMethod": "POST",
        "body": challenge,
        "headers": {
            "X-Slack-Request-Timestamp": X_Slack_Request_Timestamp,
            "X-Slack-Signature": X_Slack_Signature
        }
    }
    import lambda_handler
    response = lambda_handler.handler(event, None)
    print(response)
    if 'body' in response:
        return response['body']
    else:
        return 'success'

    # return challenge


@app.post("/slack-subscribe-event")
async def slack_subscribe_event(challenge: Dict[Any, Any]):
    print(f'payload: \n {challenge}')
    return challenge


@app.get("/test")
async def test():
    with open("index.html") as fp:
        soup = BeautifulSoup(fp, 'lxml')
    # find AFK
    search_term = 'AFK'.upper()
    print(soup.find('h2', text=search_term))
    ab = soup.find('h2', text=search_term)
    definitons = [search_term]
    if ab:
        ab = ab.find_next_sibling()
        while ab and ab.name == 'p':
            temp_string = str(ab)
            temp_string = temp_string.replace('<strong>', '*')
            temp_string = temp_string.replace('</strong>', '*')
            temp_string = temp_string.replace('<br/>', '\n')
            temp_string = temp_string.replace('<p>', '')
            temp_string = temp_string.replace('</p>', '')
            definitons.append(temp_string)
            ab = ab.find_next_sibling()
    print('\n\n'.join(definitons))
    return True
