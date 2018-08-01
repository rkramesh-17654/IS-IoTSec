from filetail import FileTail

import time

import requests
import webutils

# TODO: make these two configurable.
LOG_PATH = "snort.log"
ALERT_HANDLER_SERVER = u"0.0.0.0"

ALERT_HANDLER_URL = "/alert/"
ALERT_HANDLER_PORT = 8000


# Get the mac of the card we will use for the control plane. It will be used as the ID for this umbox.
LOCAL_MAC = webutils.local_mac_for_remote_ip(ALERT_HANDLER_SERVER)

patterns = []
patterns.append({'search_text': 'DEFAULT_CRED', 'alert_text': 'login with default credentials'})
patterns.append({'search_text': 'MULTIPLE_LOGIN', 'alert_text': 'multiple login attempts in 30 min'})

def send_request_to_handler(umbox_id, alert_text):
    """A generic API request to Alert Handler."""

    url = "http://" + str(ALERT_HANDLER_SERVER) + ":" + str(ALERT_HANDLER_PORT) + ALERT_HANDLER_URL
    print (url)
    headers = {}
    headers["Content-Type"] = "application/json"

    payload = {}
    payload['umbox'] = umbox_id
    payload['alert'] = alert_text

    req = requests.Request('POST', url, headers=headers, json=payload)
    prepared = req.prepare()
    webutils.pretty_print_POST(prepared)

    reply = requests.post(url, json=payload, headers=headers)

    print (reply)
    print (reply.content)
    return reply.content


tail = FileTail("snort.log")
for line in tail:
    for pattern in patterns:
        if pattern['search_text'] in line:
            send_request_to_handler(umbox_id=LOCAL_MAC, alert_text=pattern['alert_text'])
            

