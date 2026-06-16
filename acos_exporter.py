import json
import yaml
import sys
import os
from threading import Lock

import prometheus_client
import requests
import urllib3
from flask import Response, Flask, request
from prometheus_client import Gauge
import logging
from logging.handlers import RotatingFileHandler

UNDERSCORE = "_"
SLASH = "/"
HYPHEN = "-"
PLUS = "+"

LOG_FILE_SIZE = 5*1024*1024
API_TIMEOUT = 5
# batch-get can legitimately take longer than a single auth call; keep it under
# the Prometheus scrape_timeout (15s) so a slow/hung device can't wedge the worker.
BATCH_TIMEOUT = 12

# An expired/invalid A10 token comes back as HTTP 401/403 - that status is the
# reliable signal we key on. The keyword list is only a fallback for devices that
# answer 200 with an error body. We have seen more than one body shape, so match
# against all of them:
#   A10 AxAPI:  {"response": {"err": {"msg": "... Unauthorized ..."}}}
#   DRF-style:  {"detail": "Authentication credentials were not provided.",
#                "code": "not_authenticated"}
AUTH_ERROR_KEYWORDS = (
    "unauthorized", "not authorized", "not_authenticated", "not authenticated",
    "authentication credentials", "invalid session", "session expired",
    "session id", "expired", "forbidden",
)


def is_auth_error(status_code, response):
    if status_code in (401, 403):
        return True
    if not isinstance(response, dict):
        return False
    err = response.get("response")
    err_msg = ""
    if isinstance(err, dict) and isinstance(err.get("err"), dict):
        err_msg = str(err["err"].get("msg", ""))
    blob = " ".join((
        str(response.get("detail", "")),
        str(response.get("code", "")),
        err_msg,
    )).lower()
    return any(keyword in blob for keyword in AUTH_ERROR_KEYWORDS)

global_api_collection = dict()
global_stats = dict()

app = Flask(__name__)

_INF = float("inf")

lock1 = Lock()
tokens = dict()


def get_valid_token(host_ip, to_call=False):
    global tokens
    lock1.acquire()
    try:
        if host_ip in tokens and not to_call:
            return tokens[host_ip]
        else:
            token = ""
            if host_ip not in tokens or to_call:
                token = getauth(host_ip)
            if not token:
                logger.error("Auth token not received for host %s.", host_ip)
                tokens.pop(host_ip, None)
                return ""
            tokens[host_ip] = token
        return tokens[host_ip]
    finally:
        lock1.release()


def invalidate_token(host_ip):
    """Drop a cached token so the next scrape is forced to re-authenticate."""
    with lock1:
        tokens.pop(host_ip, None)


def set_logger(log_file, log_level):
    log_levels = {
                'DEBUG': logging.DEBUG,
                'INFO': logging.INFO,
                'WARN': logging.WARN,
                'ERROR': logging.ERROR,
                'CRITICAL': logging.CRITICAL,
            }
    if log_level.upper() not in log_levels:
        print(log_level.upper()+" is invalid log level, setting 'INFO' as default.")
        log_level = "INFO"
    try:
        log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')
        log_handler = RotatingFileHandler(log_file, maxBytes=LOG_FILE_SIZE, backupCount=2, encoding=None,
                                          delay=True)
        log_handler.setFormatter(log_formatter)
        log_handler.setLevel(log_levels[log_level.upper()]) # log levels are in order, DEBUG includes logging at each level
    except Exception as e:
        raise Exception('Error while setting logger config.')

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    logger = logging.getLogger('a10_prometheus_exporter_logger')
    logger.setLevel(log_levels[log_level.upper()])
    logger.addHandler(log_handler)
    # Also emit to stdout so logs show up in `kubectl logs` and get shipped to Loki.
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(log_formatter)
    stream_handler.setLevel(log_levels[log_level.upper()])
    logger.addHandler(stream_handler)
    return logger


def getLabelNameFromA10URL(api_list):
    if type(api_list) == list:
        empty_list = list()
        for api in api_list:
            labelName = api.replace(SLASH, UNDERSCORE)
            labelName = labelName.replace(HYPHEN, UNDERSCORE)
            labelName = labelName.replace(PLUS, UNDERSCORE)
            empty_list.append(labelName)   
        return empty_list
    else:
        labelName = api_list.replace(SLASH, UNDERSCORE)
        labelName = labelName.replace(HYPHEN, UNDERSCORE)
        labelName = labelName.replace(PLUS, UNDERSCORE)
        return labelName


def getauth(host):
    '''with open('config.yml') as f:
        hosts_data = yaml.safe_load(f)["hosts"]
    if host not in hosts_data:
        logger.error("Host credentials not found in creds config")
        return ''
    else:'''
    uname = os.environ.get('username','')
    pwd = os.environ.get('password','')
    if not uname:
        logger.error("username not provided.")
    if not pwd:
        logger.error("password not provided.")

    payload = {'Credentials': {'username': uname, 'password': pwd}}
    try:
        auth = json.loads(requests.post("https://{host}/axapi/v3/auth".format(host=host), json=payload,
                                        verify=False, timeout=API_TIMEOUT).content.decode('UTF-8'))
    except requests.exceptions.RequestException as e:
        logger.error("Auth request to %s failed: %s", host, e)
        return ''

    if 'authresponse' not in auth:
        logger.error("Host credentials are not correct")
        return ''
    return 'A10 ' + auth['authresponse']['signature']


def get(api_endpoints, endpoint, host_ip, headers):
    try:
        body = {
            "batch-get-list": list()
        }
        for api_endpoint in api_endpoints:
            body["batch-get-list"].append({"uri": "/axapi/v3" + api_endpoint })
          
        batch_endpoint = "/batch-get"
        url = endpoint + batch_endpoint
        logger.info("Uri - %s", url)
        raw = requests.post(url, data=json.dumps(body), headers=headers,
                            verify=False, timeout=BATCH_TIMEOUT)
        response = json.loads(raw.content.decode('UTF-8'))
        logger.debug("AXAPI batch response - %s", response)

        if is_auth_error(raw.status_code, response):
            # Cached token is stale/expired (e.g. HTTP 401 not_authenticated).
            # Force a fresh login and retry the batch once.
            logger.warning("Auth rejected (status=%s) for host %s; refreshing token and retrying.",
                           raw.status_code, host_ip)
            token = get_valid_token(host_ip, to_call=True)
            if token:
                headers = {'content-type': 'application/json', 'Authorization': token}
                raw = requests.post(url, data=json.dumps(body), headers=headers,
                                    verify=False, timeout=BATCH_TIMEOUT)
                response = json.loads(raw.content.decode('UTF-8'))
            else:
                logger.error("Token refresh failed for host %s; will retry on next scrape.", host_ip)
        elif isinstance(response, dict) and isinstance(response.get('response'), dict) \
                and 'err' in response['response']:
            logger.error("AXAPI error for host %s - %s",
                         host_ip, response['response']['err'].get('msg'))
    except Exception as e:
        logger.exception("Exception during batch-get for host %s: %s", host_ip, e)
        # Drop the token so a connection/parse failure can't pin us to a bad session.
        invalidate_token(host_ip)
        response = {}
    return response


def get_partition(endpoint, headers):
    partition_endpoint = "/active-partition"
    response = json.loads(requests.get(endpoint + partition_endpoint, headers=headers, verify=False).content.decode('UTF-8'))
    return "partition - "+str(response)


def change_partition(partition, endpoint, headers):
    partition_endpoint = "/active-partition/"+ str(partition)
    logger.info("Uri - " + endpoint + partition_endpoint)
    try:
        requests.post(endpoint + partition_endpoint, headers=headers, verify=False)
    except Exception as e:
        logger.exception(e)
    logger.info("Partition changed to " + partition)

@app.route("/")
def default():
    return "Please provide /metrics?query-params!"

def generate_metrics(resp_data, api_name, partition, host_ip, key, res):
    api = str(api_name)
    if api.startswith("_"):
        api = api[1:]

    current_api_stats = dict()
    if api in global_api_collection:
        current_api_stats = global_api_collection[api]
        # This section maintains local dictionary  of stats or rate fields against Gauge objects.
        # Code handles the duplication of key_name in time series database
        # by referring the global dictionary of key_name and Gauge objects.
    for key in resp_data:
        org_key = key
        if HYPHEN in key:
            key = key.replace(HYPHEN, UNDERSCORE)
        if key not in global_stats:
            current_api_stats[key] = Gauge(key, "api-" + api + "key-" + key,
                                            labelnames=(["api_name", "partition", "host"]), )
            current_api_stats[key].labels(api_name=api, partition=partition, host=host_ip).set(resp_data[org_key])
            global_stats[key] = current_api_stats[key]
        elif key in global_stats:
            global_stats[key].labels(api_name=api, partition=partition, host=host_ip).set(resp_data[org_key])

    global_api_collection[api] = current_api_stats

    for name in global_api_collection[api]:
        res.append(prometheus_client.generate_latest(global_api_collection[api][name]))
    return res


def parse_recursion(event, api_name, api_response, partition, host_ip, key,res, recursion = False):
    resp_data = dict()
    if event == None:
        return
    if type(event) == dict and "stats" not in event and "rate" not in event:
        for item in event:
            parse_recursion(event[item], api_name, api_response, partition, host_ip, key,res, recursion = True)
                               
    elif type(event) == dict and "stats" in event:
        resp_data = event.get("stats", {})
        if recursion:
            api_name_slash = event.get("a10-url", "")
            api_name = api_name_slash.replace("/axapi/v3","")
            api_name = getLabelNameFromA10URL(api_name)
        res = generate_metrics(resp_data, api_name, partition, host_ip, key,res)
        
    elif type(event) == dict and "rate" in event:
        resp_data = event.get("rate", {})
        if recursion:
            api_name_slash = event.get("a10-url", "")
            api_name = api_name_slash.replace("/axapi/v3","")
            api_name = getLabelNameFromA10URL(api_name)
        res = generate_metrics(resp_data, api_name, partition, host_ip, key,res)
        
    else:
        logger.error("Stats not found for API name '{}' with response {}.".format(api_name, api_response))
        #return "Stats not found for API name '{}' with response {}.".format(api_name, api_response)
    
    return res

@app.route("/metrics")
def generic_exporter():
    logger.debug("---------------------------------------------------------------------------------------------------")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    host_ip = request.args.get("host_ip", "") or os.environ.get("A10_HOST", "")
    api_endpoints = request.args.getlist("api_endpoint")
    if not api_endpoints:
        with open("apis.txt") as file:
            default_endpoint = file.readlines()   
            default_endpoint = [endpoint.strip() for endpoint in default_endpoint]
        api_endpoints = default_endpoint
        logger.error("api_endpoint are of default")
        
    api_names = getLabelNameFromA10URL(api_endpoints)
    partition = request.args.get("partition", "shared")
    res = []
    if not host_ip:
        logger.error("host_ip is required. Exiting API endpoints - {}".format(api_endpoints))
        return "host_ip is required. Exiting API endpoints - {}".format(api_endpoints)
   
    logger.info("Host = " + host_ip + "\t" +
                "API = " + str(api_names))
    logger.info("Endpoint = " + str(api_endpoints))
    token = get_valid_token(host_ip)
    if not token:
        return "Authentication token not received."
    endpoint = "https://{host_ip}/axapi/v3".format(host_ip=host_ip)
    headers = {'content-type': 'application/json', 'Authorization': token}

    logger.debug(get_partition(endpoint, headers))
    if "shared" not in partition:
        try:
            change_partition(partition, endpoint, headers)
            response = get(api_endpoints, endpoint, host_ip, headers)
        finally:
            change_partition("shared", endpoint, headers)
    else:
        response = get(api_endpoints, endpoint, host_ip, headers)

    api_counter = 0
    batch_list = response.get("batch-get-list", [])
    for response in batch_list:
        api_endpoint = api_endpoints[api_counter]
        api_name = api_names[api_counter]
        logger.debug("name = " + api_name)
        api_response = response.get("resp", {})
        logger.debug("API \"{}\" Response - {}".format(api_name, str(api_response)))
        api_counter += 1
        try:
            key = list(api_response.keys())[0]
            event = api_response.get(key, {})
            res = parse_recursion(event, api_name, api_response, partition, host_ip, key,res)
                 
        except Exception as ex:
            logger.exception(ex.args[0])
            return api_endpoint + " has something missing."
    logger.debug("Final Response - " + str(res))
    return Response(res, mimetype="text/plain")


def main():
    app.run(debug=True, port=9734, host='0.0.0.0')


if __name__ == '__main__':
    try:
        #with open('config.yml') as f:
            #log_data = yaml.safe_load(f).get("log", {})
        logger = set_logger("logs.log", "INFO")
        logger.info("Starting exporter")
        main()
    except Exception as e:
        print(e)
        sys.exit()