"""    Fortinet FortiNDR Cloud Integration for Cortex XSOAR (aka Demisto)

       This integration allows fetching detections, entities, events and
       saved searches from Fortinet FortiNDR Cloud APIs, also allows for
       some management operations like creating scheduled pcap tasks,
       updating detection rules and resolving detections.
"""

import json

from fnc import FncClient, FncClientLogger
from fnc.api import ApiContext, EndpointKey, FncApiClient, FncRestClient
from fnc.errors import ErrorMessages, ErrorType, FncClientError

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

USER_AGENT = "Fnc_Cortex.v1.1.0"
HISTORY_LIMIT = 500


class FncCortexRestClient(FncRestClient):
    client: BaseClient

    def __init__(self):
        # The base_url value is ignored. The full_url argument is used instead. Rather than construct the url
        # using the base url, we use the full url received from the client library.
        self.client = BaseClient(base_url="ToBeIgnored")

    def validate_request(self, req_args: dict):
        if not req_args or "url" not in req_args:
            raise FncClientError(
                error_type=ErrorType.REQUEST_VALIDATION_ERROR,
                error_message=ErrorMessages.REQUEST_URL_NOT_PROVIDED,
            )

        if "method" not in req_args:
            raise FncClientError(
                error_type=ErrorType.REQUEST_VALIDATION_ERROR,
                error_message=ErrorMessages.REQUEST_METHOD_NOT_PROVIDED,
            )

    def send_request(self, req_args: dict = {}):
        url = req_args["url"]
        method = req_args["method"]
        headers = req_args.get("headers", {})
        timeout = req_args.get("timeout", 70)
        parameters = req_args.get("params", {})
        json_data = req_args.get("json", None)
        data = req_args.get("data", None)

        return self.client._http_request(
            method=method,
            full_url=url,
            params=parameters,
            data=data,
            json_data=json_data,
            headers=headers,
            timeout=timeout,
            resp_type="response"
        )


# implement a logger class using FncClientLogger
class FncCortexLoggerCollector(FncClientLogger):
    list_of_logs: list[tuple[str, str]] = []

    def get_logs(self):
        return self.list_of_logs

    def clear_logs(self):
        self.list_of_logs.clear()

    def info(self, msg):
        info_log = ('info', msg)
        self.list_of_logs.append(info_log)

    def debug(self, msg):
        info_log = ('debug', msg)
        self.list_of_logs.append(info_log)

    def warning(self, msg):
        info_log = ('info', msg)
        self.list_of_logs.append(info_log)

    def critical(self, msg):
        info_log = ('error', msg)
        self.list_of_logs.append(info_log)

    def error(self, msg):
        info_log = ('error', msg)
        self.list_of_logs.append(info_log)


# Helper Methods

def flush_logs(logger: FncCortexLoggerCollector):
    for level, log in logger.get_logs():
        if level == 'info':
            demisto.info(log)
        elif level == 'debug':
            demisto.debug(log)
        else:
            demisto.error(log)
    logger.clear_logs()


def _create_cortex_incidents(detections):
    incidents: List[Dict[str, Any]] = []

    if len(detections) > 0:
        demisto.info(f"Creating incidents for {len(detections)} detections.")
    else:
        demisto.info("No detections was retrieved.")

    for detection in detections:
        severity = mapSeverity(detection["rule_severity"])
        incident = {
            "name": "Fortinet FortiNDR Cloud - " + detection["rule_name"],
            "occurred": detection["created"],
            "severity": severity,
            "details": detection["rule_description"],
            "dbotMirrorId": detection["uuid"],
            "rawJSON": json.dumps(detection),
            "type": "Fortinet FortiNDR Cloud Detection",
            "CustomFields": {  # Map specific XSOAR Custom Fields
                "fortindrcloudcategory": detection["rule_category"],
                "fortindrcloudconfidence": detection["rule_confidence"],
                "fortindrcloudstatus": detection["status"],
            },
        }

        incidents.append(incident)

    return incidents


def _split_multivalue_args(args: dict, multiple_values: list = []) -> dict:
    """Update the arguments contained in the multiple_values list
    from a comma separated string into a list of string.
    :parm Dict[str, Any] args: Arguments to be processed
    :parm List[str] multiple_values: Arguments with multiple values
    :return the processed list of arguments
    :rtype str
    """
    for arg in multiple_values:
        if arg in args:
            value = args[arg].split(",")
            value = [v.strip() for v in value if v.strip()]
            args[arg] = value

    return args


def _handle_fnc_endpoint(api_client: FncApiClient, endpoint: EndpointKey, param: dict):
    demisto.info(f"Handling {endpoint.value} Request.")

    param.pop("context", None)

    response = None

    logger: FncCortexLoggerCollector = api_client.get_logger()
    try:
        response = api_client.call_endpoint(endpoint=endpoint, args=param)
        flush_logs(logger=logger)
        demisto.info(f"{endpoint.value} successfully completed.")
        return response
    except FncClientError as e:
        flush_logs(logger=logger)
        demisto.error(f"{endpoint.value} Request Failed. [{str(e)}]")
        raise e


def formatEvents(r_json):
    """Format the events in the response to be shown as a table.
    :parm Any r_json: Received response
    :return The formated response
    :rtype list
    """
    key = "data"
    header_key = "columns"

    if r_json and key in r_json:
        data = r_json.pop(key, [])
        headers = r_json.pop(header_key, [])
        new_data = [dict(zip(headers, values)) for values in data]

    return new_data


def get_poll_detections_request_params(args: Dict) -> Dict:
    demisto.info("Retrieving params for Detections polling.")

    config = args

    request_params = {
        'include_signature': True,
        'include_description': True,

        'start_date': config.get("first_fetch", ""),
        'polling_delay': config.get("delay", 10),
        'account_uuid': config.get("account_uuid", ""),

        'status': config.get("status", ""),
        'pull_muted_rules': config.get("muted_rule", False),
        'pull_muted_devices': config.get("muted_device", False),
        'pull_muted_detections': config.get("muted", False),
    }

    demisto.info("Arguments retrieved")

    return request_params


def mapSeverity(severity) -> int:
    match severity:
        case "high":
            return 3
        case "moderate":
            return 2
        case "low":
            return 1
        case _:
            return 0

### Commands Methods ###


def commandTestModule(client: FncApiClient):
    """Test that the module is up and running."""
    demisto.info("Testing connection to FortiNDR Cloud Services")

    try:
        commandGetSensors(client=client, args={})
        demisto.info("Connection successfully verified.")
        return "ok"
    except Exception as e:
        demisto.error(f"Module test failed: {e}")
        raise e


# Sensors API commands


def commandGetSensors(client: FncApiClient, args):
    """Get a list of all sensors."""
    demisto.info("CommandGetSensors has been called.")

    endpoint = EndpointKey.GET_SENSORS

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    prefix = "FortiNDRCloud.Sensors"
    key = "sensors"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Sensors."

    demisto.info("CommandGetSensors successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetDevices(client: FncApiClient, args):
    """Get the number of devices."""
    demisto.info("CommandGetDevices has been called.")

    endpoint = EndpointKey.GET_DEVICES

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    prefix = "FortiNDRCloud.Devices"
    key = "device_list"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if 'devices' not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    result = result["devices"]

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Devices."

    demisto.info("CommandGetDevices successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetTasks(client: FncApiClient, args):
    """Get a list of all the PCAP tasks."""
    demisto.info("commandGetTasks has been called.")

    endpoint = EndpointKey.GET_TASKS

    taskid = args.pop("task_uuid", "")
    if taskid:
        endpoint = EndpointKey.GET_TASK
        args.update({"task_id": taskid})

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    prefix = "FortiNDRCloud.Tasks"
    key = "pcap_task" if taskid else "pcaptasks"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Tasks."

    demisto.info("CommandGetTasks successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandCreateTask(client: FncApiClient, args):
    """Create a new PCAP task."""
    demisto.info("commandCreateTask has been called.")

    endpoint = EndpointKey.CREATE_TASK

    if "sensor_ids" in args:
        args = _split_multivalue_args(args=args, multiple_values=["sensor_ids"])
    else:
        args.update("sensor_ids", [])

    result = _handle_fnc_endpoint(api_client=client, endpoint=endpoint, param=args)

    key = "pcaptask"

    if key in result:
        demisto.info("CommandCreateTask successfully completed.")

        return CommandResults(readable_output="Task created successfully")
    else:
        raise Exception(f"Task creation failed with: {result}")


def commandGetEventsTelemetry(client: FncApiClient, args):
    """Get event telemetry data grouped by time"""
    demisto.info("commandGetEventsTelemetry has been called.")

    endpoint = EndpointKey.GET_TELEMETRY_EVENTS

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    prefix = "FortiNDRCloud.Telemetry.Events"
    key = "data"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Event Telemetry."

    demisto.info("commandGetEventsTelemetry successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=formatEvents(result)
    )


def commandGetNetworkTelemetry(client: FncApiClient, args):
    """Get network telemetry data grouped by time"""
    demisto.info("commandGetNetworkTelemetry has been called.")

    endpoint = EndpointKey.GET_TELEMETRY_NETWORK

    latest_each_month = args.pop("latest_each_month", False)
    if latest_each_month:
        args.update({"latest_each_month": True})

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    prefix = "FortiNDRCloud.Telemetry.NetworkUsage"
    key = "network_usage"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Network Telemetry."

    demisto.info("commandGetNetworkTelemetry successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetPacketstatsTelemetry(client: FncApiClient, args):
    """Get packetstats telemetry data grouped by time."""
    demisto.info("commandGetPacketstatsTelemetry has been called.")

    endpoint = EndpointKey.GET_TELEMETRY_PACKETSTATS

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    prefix = "FortiNDRCloud.Telemetry.Packetstats"
    key = "data"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Packetstats Telemetry."

    demisto.info("commandGetPacketstatsTelemetry successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


# Entity API commands


def commandGetEntitySummary(client: FncApiClient, args):
    """Get entity summary information about an IP or domain."""
    demisto.info("commandGetEntitySummary has been called.")
    endpoint = EndpointKey.GET_ENTITY_SUMMARY

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    prefix = "FortiNDRCloud.Entity.Summary"
    key = "summary"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Entity Summary."

    demisto.info("commandGetEntitySummary successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetEntityPdns(client: FncApiClient, args: Dict[str, Any]):
    """Get passive DNS information about an IP or domain."""
    demisto.info("commandGetEntityPdns has been called.")

    endpoint = EndpointKey.GET_ENTITY_PDNS

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    prefix = "FortiNDRCloud.Entity.PDNS"
    key = "passivedns"

    if not result:
        raise Exception(f"We receive an invalid response from the server({result})")

    if "result_count" in result and result.get("result_count") == 0:
        return "We could not find any result for Get Entity PDNS."

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Entity PDNS."

    demisto.info("commandGetEntityPdns successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetEntityDhcp(client: FncApiClient, args: Dict[str, Any]):
    """Get DHCP information about an IP address."""
    demisto.info("commandGetEntityDhcp has been called.")

    endpoint = EndpointKey.GET_ENTITY_DHCP

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    prefix = "FortiNDRCloud.Entity.DHCP"
    key = "dhcp"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if "result_count" in result and result.get("result_count") == 0:
        return "We could not find any result for Get Entity DHCP."

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Entity DHCP."

    demisto.info("commandGetEntityDhcp successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetEntityFile(client: FncApiClient, args):
    """Get entity information about a file"""
    demisto.info("commandGetEntityFile has been called.")

    endpoint = EndpointKey.GET_ENTITY_FILE

    hash = args.pop("hash", "")
    args.update({"entity": hash})

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    prefix = "FortiNDRCloud.Entity.File"
    key = "file"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Entity File."

    demisto.info("commandGetEntityFile successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


# Detections API commands


def commandFetchIncidents(
    client: FncApiClient, params, integration_context
) -> tuple[ApiContext, list[Dict[str, Any]]]:
    logger: FncCortexLoggerCollector = client.get_logger()
    demisto.info("CommandFetchIncidents has been called.")

    params = get_poll_detections_request_params(args=params)

    last_detection = integration_context.get('last_poll', None)
    if last_detection:
        demisto.info("Last checkpoint was: ", last_detection)

    history = {}
    last_history = integration_context.get('last_history', None)
    if last_history:
        demisto.info("Last history was: ", last_history)
        history = json.loads(last_history)

    incidents: List[Dict[str, Any]] = []

    try:
        # We restore the context using the persisted values of the
        # last_detection(checkpoint) and the history if they exist
        # Otherwise, we initialize them by calling the get splitted
        # context method.

        context: ApiContext
        h_context: ApiContext

        if last_detection:
            demisto.info("Restoring the Context")
            context = ApiContext()
            context.update_checkpoint(checkpoint=last_detection)
            h_context = ApiContext()
            h_context.update_history(history=history)
        else:
            demisto.info("Initializing the Context")
            h_context, context = client.get_splitted_context(params)

        flush_logs(logger=logger)

        # Pull current detections
        demisto.info("Polling current detections")

        detections = []
        for response in client.continuous_polling(context=context, args=params):
            flush_logs(logger=logger)
            c_detections = response.get('detections', [])
            detections.extend(c_detections)
        context.clear_args()

        # Pull next piece of history detections
        demisto.info('Polling historical data')

        params.update({'limit': HISTORY_LIMIT})
        for response in client.poll_history(context=h_context, args=params):
            flush_logs(logger=logger)
            h_detections = response.get('detections', [])
            detections.extend(h_detections)

        h_context.clear_args()
        incidents = _create_cortex_incidents(detections=detections)

        # checkpoint for the first Detection iteration
        last_poll = context.get_checkpoint()
        history = h_context.get_remaining_history()

        demisto.debug("Updating last poll checkpoint")
        integration_context["last_poll"] = last_poll

        last_history = json.dumps(history)
        demisto.debug("Updating last history checkpoint.")
        integration_context["last_history"] = last_history

        demisto.info(f"Last poll checkpoint set at {last_poll}")
        demisto.info(f"Last history checkpoint set at {last_history}")

        demisto.info("Completed processing Detections")
    except Exception as e:
        flush_logs(logger=logger)
        demisto.error(f"Fetch Incidents failed: {e}")
        raise e

    return integration_context, incidents


def commandGetDetections(client: FncApiClient, args):
    """Get a list of detections."""
    demisto.info("commandGetDetections has been called.")

    endpoint = EndpointKey.GET_DETECTIONS

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    prefix = "FortiNDRCloud.Detections"
    key = "detections"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Detections."

    demisto.info("commandGetDetections successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetDetectionEvents(client: FncApiClient, args):
    """Get a list of the events associated to a specific detection."""
    demisto.info("CommandGetDetectionEvents has been called.")

    endpoint = EndpointKey.GET_DETECTION_EVENTS

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    events = []
    detection_uuid = args.get("detection_uuid", "")
    for event in result.get("events", []):
        rule_uuid = event.get("rule_uuid", "")
        event = event.get("event", {})
        if event:
            event["detection_uuid"] = detection_uuid
            event["rule_uuid"] = rule_uuid
            events.append(event)
    result["events"] = events

    prefix = "FortiNDRCloud.Detections"
    key = "events"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Detections Events."

    demisto.info("commandGetDetectionEvents successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetDetectionRules(client: FncApiClient, args):
    """Get a list of detection rules."""
    demisto.info("CommandGetDetectionRules has been called.")

    endpoint = EndpointKey.GET_RULES

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    prefix = "FortiNDRCloud.Rules"
    key = "rules"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Detection Rules."

    demisto.info("commandGetDetectionRules successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetDetectionRuleEvents(client: FncApiClient, args):
    """Get a list of the events that matched on a specific rule."""
    demisto.info("CommandGetDetectionRuleEvents has been called.")

    endpoint = EndpointKey.GET_RULE_EVENTS

    rule = args.pop("rule_uuid", "")
    args.update({"rule_id": rule})

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    prefix = "FortiNDRCloud.Detections"
    key = "events"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Detections Rule Events."

    demisto.info("commandGetDetectionRuleEvents successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandCreateDetectionRule(client: FncApiClient, args):
    """Create a new detection rule."""
    demisto.info("commandCreateDetectionRule has been called.")

    endpoint = EndpointKey.CREATE_RULE

    if "run_account_uuids" in args:
        args = _split_multivalue_args(args=args, multiple_values=["run_account_uuids"])

    if "device_ip_fields" in args:
        args = _split_multivalue_args(args=args, multiple_values=["device_ip_fields"])
    else:
        args.update({"device_ip_fields": ["DEFAULT"]})

    if "indicator_fields" in args:
        args = _split_multivalue_args(args=args, multiple_values=["indicator_fields"])

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )

    if "rule" in result:

        demisto.info("commandCreateDetectionRule successfully completed.")

        return CommandResults(readable_output="Rule created successfully")
    else:
        raise Exception(f"Rule creation failed with: {result}")


def commandResolveDetection(client: FncApiClient, args):
    """Resolve a specific detection."""
    demisto.info("commandResolveDetection has been called.")

    endpoint = EndpointKey.RESOLVE_DETECTION

    if "detection_uuid" not in args:
        raise Exception(
            "Detection cannot be resolved: No detection_uuid has been provided."
        )

    if "resolution" not in args:
        raise Exception(
            "Detection cannot be resolved: No resolution has been provided."
        )

    detection = args.pop("detection_uuid", "")
    args.update({"detection_id": detection})
    result = _handle_fnc_endpoint(api_client=client, endpoint=endpoint, param=args)

    if not result:

        demisto.info("commandResolveDetection successfully completed.")

        return CommandResults(readable_output="Detection resolved successfully")
    else:
        raise Exception(f"Detection resolution failed with: {result}")


def main():
    # get command and args
    command = demisto.command()
    params = demisto.params()

    demisto.info(f"Starting to handle command {command}")

    logged_params = params.copy()
    if "api_key" in logged_params:
        logged_params["api_key"] = "*********"

    args: Dict[str, Any] = demisto.args()

    # initialize common args
    api_key = params.get("api_key", '')
    domain = params.get("domain", None)

    # attempt command execution
    try:
        restClient = FncCortexRestClient()
        logger_collector = FncCortexLoggerCollector()

        fClient = FncClient.get_api_client(
            name=USER_AGENT,
            api_token=api_key,
            domain=domain,
            rest_client=restClient,
            logger=logger_collector
        )

        if isinstance(fClient, FncApiClient):
            fnc_api_Client = fClient

        if command == "test-module":
            return_results(commandTestModule(client=fnc_api_Client))

        elif command == "fetch-incidents":
            integration_context, incidents = commandFetchIncidents(
                fnc_api_Client, params, demisto.getIntegrationContext()
            )
            # saves context for next run
            demisto.info("Saving integration context in Cortex")
            demisto.setIntegrationContext(integration_context)

            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.info(f"Sending {len(incidents)} incidents to Cortex")
            demisto.incidents(incidents=incidents)

            demisto.info("Incidents successfully sent.")

        elif command == "fortindr-cloud-get-sensors":
            return_results(commandGetSensors(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-devices":
            return_results(commandGetDevices(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-tasks":
            return_results(commandGetTasks(fnc_api_Client, args))

        elif command == "fortindr-cloud-create-task":
            return_results(commandCreateTask(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-telemetry-events":
            return_results(
                commandGetEventsTelemetry(fnc_api_Client, args)
            )

        elif command == "fortindr-cloud-get-telemetry-network":
            return_results(
                commandGetNetworkTelemetry(fnc_api_Client, args)
            )

        elif command == "fortindr-cloud-get-telemetry-packetstats":
            return_results(
                commandGetPacketstatsTelemetry(fnc_api_Client, args)
            )

        elif command == "fortindr-cloud-get-detections":
            return_results(commandGetDetections(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-detection-events":
            return_results(commandGetDetectionEvents(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-detection-rules":
            return_results(commandGetDetectionRules(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-detection-rule-events":
            return_results(commandGetDetectionRuleEvents(fnc_api_Client, args))

        elif command == "fortindr-cloud-resolve-detection":
            return_results(commandResolveDetection(fnc_api_Client, args))

        elif command == "fortindr-cloud-create-detection-rule":
            return_results(commandCreateDetectionRule(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-entity-summary":
            return_results(commandGetEntitySummary(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-entity-pdns":
            return_results(commandGetEntityPdns(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-entity-dhcp":
            return_results(commandGetEntityDhcp(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-entity-file":
            return_results(commandGetEntityFile(fnc_api_Client, args))

    # catch exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}", str(e)
        )


if __name__ in ("__main__", "__builtin__", "builtins"):

    main()
