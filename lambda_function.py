import json
import logging
import os
import time
import datetime
from urllib.parse import urlencode

import botocore
import urllib3
import boto3
from botocore.exceptions import ClientError
from urllib3 import Timeout

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

http = urllib3.PoolManager(cert_reqs='CERT_NONE')

root = logging.getLogger()
if root.handlers:
    for handler in root.handlers:
        root.removeHandler(handler)
logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants for engine status id
ENGINE_STATUS_OFFLINE = 0
ENGINE_STATUS_BLOCKED = 1
ENGINE_STATUS_SCANNINGANDBLOCKED = 2
ENGINE_STATUS_SCANNING = 3
ENGINE_STATUS_IDLE = 4

# Constants for scan stage id
SCAN_STAGE_SCANNING = 4
SCAN_STAGE_CANCELED = 8
SCAN_STAGE_QUEUED = 3
engine_in_manager_ip = "10.64.10.53"

# environment variables for loc range
small_loc = int(os.getenv("small_loc"))
medium_loc = int(os.getenv("medium_loc"))
large_loc = int(os.getenv("large_loc"))
xlarge_loc = int(os.getenv("xlarge_loc"))
xxlarge_loc = int(os.getenv("xxlarge_loc"))
xxxlarge_loc = int(os.getenv("xxxlarge_loc"))


def get_cxsast_api_password():
    parameter_name = os.getenv('cxsast_api_password')
    ssm = boto3.client("ssm", region_name='ap-southeast-1')
    parameter = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
    return parameter['Parameter']['Value']


class CxSastRestApi:

    def __init__(self):
        self.logger = logging.getLogger('CxSastRestApi')
        self.logger.debug("Creating CxSastRestApi")
        self.url = os.getenv("cxsast_api_base_url")
        self.headers = None
        self.__login()
        self.logger.info("Succefully Log in to cx")

    def __login(self):
        logger.info("start login to cx")
        url = self.url + "/cxrestapi/auth/identity/connect/token"
        self.logger.debug("Logging into %s" % url)
        username = os.getenv("cxsast_api_username")
        body = ({'username': username,
                 'password': get_cxsast_api_password(),
                 'grant_type': 'password',
                 'scope': 'sast_rest_api',
                 'client_id': 'resource_owner_client',
                 'client_secret': '014DF517-39D1-4453-B7B3-9930C563627C'
                 })
        encoded_body = urlencode(body)
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        logger.info("Logging into %s" % url)
        logger.info("body username %s" % username)
        try:
            response = http.request('POST', url, headers=headers, body=encoded_body)
            json_data = json.loads(response.data.decode('utf-8'))
            token_type = json_data['token_type']
            access_t = json_data['access_token']
            token = token_type + " " + access_t
            self.headers = {
                'Authorization': token,
                'Content-Type': 'application/json;v=1.0'
            }
            logger.info("get the token")

        except urllib3.exceptions.NewConnectionError:
            self.logger.error('Could not log in to %s', url)

    def get_scan_queue(self):
        logger.info("get the scan queue")
        try:
            url = self.url + '/cxrestapi/sast/scansQueue'
            self.logger.debug("GET %s" % url)
            response = http.request('GET', url, headers=self.headers)
            json_data = json.loads(response.data.decode('utf-8'))
            logger.info("finished get the scan queue")
            return json_data

        except urllib3.exceptions.NewConnectionError:
            self.logger.error('Could not get Checkmarx Scan Queue')

    def get_engine_by_id(self, engine_id):
        engines = self.get_engines()
        for engine in engines:
            if engine['id'] == engine_id:
                return engine
        return None

    def get_engine_by_name(self, name):
        engines = self.get_engines()
        for engine in engines:
            if engine['name'] == name:
                return engine
        return None

    def get_engine_by_uri(self, uri):
        engines = self.get_engines()
        for engine in engines:
            if engine['uri'] == uri:
                return engine
        return None

    def update_engine(self, engine_id, name, uri, max_scans, min_loc, max_loc, is_blocked):
        try:
            url = self.url + '/cxrestapi/sast/engineServers/' + str(engine_id)
            body = {
                'name': name,
                'uri': uri,
                'minLoc': min_loc,
                'maxLoc': max_loc,
                'isBlocked': is_blocked,
                'maxScans': max_scans
            }
            encoded_body = json.dumps(body)
            response = http.request('PUT', url, headers=self.headers, body=encoded_body)
            response_data = response.data.decode('utf-8')
            json_data = json.loads(response_data)
            logger.debug(response)
            if response.status == 200:
                self.logger.info(
                    f"Updated engine name: {name} id: {json_data['id']} uri: {uri} max_scans: {max_scans}"
                    f" min_loc: {min_loc} max_loc: {max_loc} is_blocked: {is_blocked}"
                )
            elif response.status == 400:
                self.logger.warning(response_data)
            return json_data
        except urllib3.exceptions.NewConnectionError:
            self.logger.error('Could not register Checkmarx Engine ' + str(name) + ' with url ' + str(uri))

    def get_engines(self):
        try:
            url = self.url + '/cxrestapi/sast/engineServers'
            self.logger.debug("GET %s" % url)
            response = http.request('GET', url, headers=self.headers)
            json_data = json.loads(response.data.decode('utf-8'))
            return json_data
        except urllib3.exceptions.NewConnectionError:
            self.logger.error('Could not get Checkmarx Engines')

    def register_engine(self, name, uri, max_scans, min_loc, max_loc, is_blocked=False):
        try:
            url = self.url + '/cxrestapi/sast/engineServers'
            body = {
                'name': name,
                'uri': uri,
                'minLoc': min_loc,
                'maxLoc': max_loc,
                'isBlocked': 'false' if not is_blocked else 'true',
                'maxScans': max_scans
            }
            encoded_body = json.dumps(body)
            response = http.request('POST', url, headers=self.headers, body=encoded_body)
            response_data = response.data.decode('utf-8')
            json_data = json.loads(response_data)
            if response.status == 201:
                self.logger.info(
                    f"Registered name: {name} id: {json_data['id']} uri: {uri} max_scans: {max_scans}"
                    f" min_loc: {min_loc} max_loc: {max_loc}"
                )
            elif response.status == 400:
                self.logger.warning(response_data)
            return json_data
        except urllib3.exceptions.NewConnectionError:
            self.logger.error('Could not register Checkmarx Engine ' + str(name) + ' with url ' + str(uri))

    def unregister_engine(self, engine_id):
        try:
            url = self.url + '/cxrestapi/sast/engineServers/' + str(engine_id)
            response = http.request('DELETE', url, headers=self.headers)
            if response.status == 204:
                self.logger.info("Unregistered engine id %s" % engine_id)
            elif response.status == 400:
                response_data = response.data.decode('utf-8')
                self.logger.warning(response_data)
        except urllib3.exceptions.NewConnectionError:
            self.logger.error('Could not unregister Checkmarx Engine ' + str(engine_id))

    def delete_scan(self, scan_id):
        try:
            url = self.url + '/cxrestapi/sast/scans/' + str(scan_id)
            response = http.request('DELETE', url, headers=self.headers)
            if response.status == 202:
                self.logger.info("Deleted scan id %s" % scan_id)
            elif response.status == 400:
                response_data = response.data.decode('utf-8')
                self.logger.warning(response_data)
        except urllib3.exceptions.NewConnectionError:
            self.logger.error('Could not delete scan ' + str(scan_id))

    def get_all_engine_server_details(self):
        try:
            url = self.url + "/cxrestapi/sast/engineServers"
            response = http.request('GET', url, headers=self.headers)
            json_data = json.loads(response.data.decode('utf-8'))
            if "invalid" in "{}".format(json_data):
                return []
            return json_data
        except urllib3.exceptions.NewConnectionError:
            self.logger.error('Could not get engine server details ')

    def register_local_engine_if_missing(self, uri):
        """
        the engine from manager is used as blocked engine to prevent scan failing when there are no engines
        :param uri:
        :return:
        """
        engine = self.get_engine_by_uri(uri)
        if engine:
            return
        self.register_engine(name="Local", uri=uri, max_scans=1, min_loc=0, max_loc=100000, is_blocked=True)


class ScanQueueDepth:

    def __init__(self, cx_api):
        self.logger = logging.getLogger('ScanQueueDepthMonitor')
        self.logger.debug("Creating ScanQueueDepthMonitor")
        self.cxsast_api = cx_api

        self.small_loc = small_loc
        self.medium_loc = medium_loc
        self.large_loc = large_loc
        self.xlarge_loc = xlarge_loc
        self.xxlarge_loc = xxlarge_loc
        self.xxxlarge_loc = xxxlarge_loc

        self.small_queue_depth = 0
        self.medium_queue_depth = 0
        self.large_queue_depth = 0
        self.xlarge_queue_depth = 0
        self.xxlarge_queue_depth = 0
        self.xxxlarge_queue_depth = 0

    def __reset_queue_depth(self):
        self.small_queue_depth = 0
        self.medium_queue_depth = 0
        self.large_queue_depth = 0
        self.xlarge_queue_depth = 0
        self.xxlarge_queue_depth = 0
        self.xxxlarge_queue_depth = 0

    def calculate_queue_depth(self):
        """
        This method answer how many new servers to create for each engine size.
        The queue depth of each engine size should correspond to how many new servers should be created for each size.
        The queue depth = number of scans with queued status - number of servers currently exist
        """
        self.logger.debug('getting scan queue depth')
        self.__reset_queue_depth()
        # how many scans for each engine size
        [self.small_queue_depth, self.medium_queue_depth, self.large_queue_depth,
         self.xlarge_queue_depth,
         self.xxlarge_queue_depth,
         self.xxxlarge_queue_depth] = get_number_of_queued_scans_for_each_engine_size_in_queue()
        # how many servers for each engine size
        engines_of_each_size = get_list_of_engines_for_each_engine_size()
        self.small_queue_depth -= len(engines_of_each_size[0])
        self.medium_queue_depth -= len(engines_of_each_size[1])
        self.large_queue_depth -= len(engines_of_each_size[2])
        self.xlarge_queue_depth -= len(engines_of_each_size[3])
        self.xxlarge_queue_depth -= len(engines_of_each_size[4])
        self.xxxlarge_queue_depth -= len(engines_of_each_size[5])
        # set to 0 in case the number could be negative
        if self.small_queue_depth < 0:
            self.small_queue_depth = 0
        if self.medium_queue_depth < 0:
            self.medium_queue_depth = 0
        if self.large_queue_depth < 0:
            self.large_queue_depth = 0
        if self.xlarge_queue_depth < 0:
            self.xlarge_queue_depth = 0
        if self.xxlarge_queue_depth < 0:
            self.xxlarge_queue_depth = 0
        if self.xxxlarge_queue_depth < 0:
            self.xxxlarge_queue_depth = 0


def get_number_of_queued_scans_for_each_engine_size_in_queue():
    small_queue_depth = 0
    medium_queue_depth = 0
    large_queue_depth = 0
    xlarge_queue_depth = 0
    xxlarge_queue_depth = 0
    xxxlarge_queue_depth = 0
    current_queue = CxSastRestApi().get_scan_queue()
    for scan in current_queue:
        if scan['stage']['id'] != SCAN_STAGE_QUEUED:
            continue
        if scan['loc'] < small_loc:
            small_queue_depth += 1
        elif scan['loc'] < medium_loc:
            medium_queue_depth += 1
        elif scan['loc'] < large_loc:
            large_queue_depth += 1
        elif scan['loc'] < xlarge_loc:
            xlarge_queue_depth += 1
        elif scan['loc'] < xxlarge_loc:
            xxlarge_queue_depth += 1
        elif scan['loc'] < xxxlarge_loc:
            xxxlarge_queue_depth += 1
    return [small_queue_depth, medium_queue_depth, large_queue_depth, xlarge_queue_depth, xxlarge_queue_depth,
            xxxlarge_queue_depth]


def get_list_of_engines_for_each_engine_size():
    ec2s = Ec2Api(os.environ['CheckmarxEnvironment']).find_running_engines()
    loc_range_list = (small_loc, medium_loc, large_loc, xlarge_loc, xxlarge_loc, xxxlarge_loc)
    return [[ec2 for ec2 in ec2s if ec2.max_loc == loc] for loc in loc_range_list]


class ScanQueueDepthMetricsPublisher:

    def __init__(self, scan_queue_depth, environment):
        self.logger = logging.getLogger('ScanQueueDepthMetricsPublisher')
        self.cloudwatch = boto3.resource('cloudwatch')
        self.metric_namespace = "checkmarx/cxsast/%s" % environment
        self.metric_namespace = "Cx"
        self.scan_queue_depth = scan_queue_depth
        self.environment = environment

    @staticmethod
    def is_engine_status(ec2, status="idle"):
        instance_id = ec2.instanceid
        all_engine_servers = CxSastRestApi().get_all_engine_server_details()
        for engine in all_engine_servers:
            if engine.get("name") == instance_id and engine.get("status").get("value") == status:
                return True
        return False

    def publish(self):
        """
        Because AWS Auto Scaling Group are triggered by alarm in cloudwatch to create or terminate servers, we need to
        decide when to push the metric to let the alarms been triggered.
        To create new engines, the alarms should be triggered when there are no engines, or no idle engines.
        To terminate engines, the alarms should be triggered when there are no scans with queued status
        """
        list_of_ec2s_of_each_engine_size = get_list_of_engines_for_each_engine_size()
        engines_of_each_size_without_idle = [
            [ec2 for ec2 in group if not self.is_engine_status(ec2, status="idle")]
            for group in list_of_ec2s_of_each_engine_size
        ]

        if len(list_of_ec2s_of_each_engine_size[0]) == 0 \
                or len(engines_of_each_size_without_idle[0]) == 0 \
                or self.scan_queue_depth.small_queue_depth == 0:
            self.__put_metric_data(
                "Small Scan Queue Depth", self.scan_queue_depth.small_queue_depth, 'Count'
            )
            self.logger.info(f"Small Scan Queue Depth: {self.scan_queue_depth.small_queue_depth}")
        if len(list_of_ec2s_of_each_engine_size[1]) == 0 \
                or len(engines_of_each_size_without_idle[1]) == 0 \
                or self.scan_queue_depth.medium_queue_depth == 0:
            self.__put_metric_data(
                "Medium Scan Queue Depth", self.scan_queue_depth.medium_queue_depth, 'Count'
            )
            self.logger.info(f"Medium Scan Queue Depth: {self.scan_queue_depth.medium_queue_depth}")
        if len(list_of_ec2s_of_each_engine_size[2]) == 0 \
                or len(engines_of_each_size_without_idle[2]) == 0 \
                or self.scan_queue_depth.large_queue_depth == 0:
            self.__put_metric_data(
                "Large Scan Queue Depth", self.scan_queue_depth.large_queue_depth, 'Count'
            )
            self.logger.info(f"Large Scan Queue Depth: {self.scan_queue_depth.large_queue_depth}")
        if len(list_of_ec2s_of_each_engine_size[3]) == 0 \
                or len(engines_of_each_size_without_idle[3]) == 0 \
                or self.scan_queue_depth.xlarge_queue_depth == 0:
            self.__put_metric_data(
                "XLarge Scan Queue Depth", self.scan_queue_depth.xlarge_queue_depth, 'Count'
            )
            self.logger.info(f"XLarge Scan Queue Depth: {self.scan_queue_depth.xlarge_queue_depth}")
        if len(list_of_ec2s_of_each_engine_size[4]) == 0 \
                or len(engines_of_each_size_without_idle[4]) == 0 \
                or self.scan_queue_depth.xxlarge_queue_depth == 0:
            self.__put_metric_data(
                "XXLarge Scan Queue Depth", self.scan_queue_depth.xxlarge_queue_depth, 'Count'
            )
            self.logger.info(f"XXLarge Scan Queue Depth: {self.scan_queue_depth.xxlarge_queue_depth}")
        if len(list_of_ec2s_of_each_engine_size[5]) == 0 \
                or len(engines_of_each_size_without_idle[5]) == 0 \
                or self.scan_queue_depth.xxxlarge_queue_depth == 0:
            self.__put_metric_data(
                "XXXLarge Scan Queue Depth", self.scan_queue_depth.xxxlarge_queue_depth, 'Count'
            )
            self.logger.info(f"XXXLarge Scan Queue Depth: {self.scan_queue_depth.xxxlarge_queue_depth}")

    def __put_metric_data(self, name, value, unit):
        try:
            metric = self.cloudwatch.Metric(self.metric_namespace, name)
            metric.put_data(
                Namespace=metric.namespace,
                MetricData=[{
                    'Timestamp': datetime.datetime.utcnow(),
                    'MetricName': metric.metric_name,
                    'Value': value,
                    'Unit': unit,
                    'Dimensions': [
                        {'Name': 'Environment',
                         'Value': self.environment}
                    ]
                }]
            )
            self.logger.debug('Published: %s %s %s %s' % (self.metric_namespace, name, value, unit))
        except ClientError:
            self.logger.exception("Couldn't put data for metric %s.%s", self.metric_namespace, name)
            raise


class Ec2Api:

    def __init__(self, environment):
        self.logger = logging.getLogger("ec2api")
        self.environment = environment

    def find_running_engines(self):
        client = boto3.client('ec2')
        custom_filter = [{'Name': 'instance-state-name', 'Values': ['running']},
                         {'Name': 'tag:Environment', 'Values': [self.environment]},
                         {'Name': 'tag-key', 'Values': ['checkmarx:cxsast:engine:loc:min']}]

        servers = client.describe_instances(Filters=custom_filter)
        ec2s = []
        for reservation in servers['Reservations']:
            for instance in reservation['Instances']:
                # No private IP means we're not ready to use this server
                if instance['PrivateIpAddress'] is None:
                    continue
                else:
                    ec2s.append(Ec2Engine(instance))

        return ec2s

    def set_instance_protection(self, ec2, is_protected):
        client = boto3.client('autoscaling')
        try:
            client.set_instance_protection(
                InstanceIds=[
                    ec2.instanceid,
                ],
                AutoScalingGroupName=ec2.asg_groupname,
                ProtectedFromScaleIn=is_protected
            )
        except Exception as e:
            self.logger.warning(f"An exception occured while updating instance protection for {ec2.instanceid}")
            self.logger.exception(e)


class Ec2Engine:

    def __init__(self, instance):
        self.min_loc = int(self.__find_tag_value(instance['Tags'], 'checkmarx:cxsast:engine:loc:min'))
        self.max_loc = int(self.__find_tag_value(instance['Tags'], 'checkmarx:cxsast:engine:loc:max'))
        self.asg_groupname = self.__find_tag_value(instance['Tags'], 'aws:autoscaling:groupName')
        self.instanceid = instance['InstanceId']
        self.instancetype = instance['InstanceType']
        self.privateip = instance['PrivateIpAddress']
        self.enginename = self.instanceid
        self.max_scans = 1
        self.uri = 'http://%s:8088' % self.privateip

    @staticmethod
    def __find_tag_value(tags, key):
        for tag in tags:
            if tag['Key'] == key:
                return tag['Value']
        return None


class EngineRegistrar:

    def __init__(self, cx_api, ec2_api):
        self.logger = logging.getLogger('EngineRegistrar')
        self.cxsast_api = cx_api
        self.ec2_api = ec2_api

    def update(self):
        self.__unregister_offline_engines()
        self.__register_missing_ec2s()

    def __unregister_offline_engines(self):
        engines = self.cxsast_api.get_engines()
        for engine in engines:
            # ignore the engine in cx manager server
            if engine_in_manager_ip in engine['uri']:
                continue
            if engine['status']['id'] == ENGINE_STATUS_OFFLINE:
                self.cxsast_api.unregister_engine(engine['id'])

    @staticmethod
    def __is_engine_registered(engines, name):
        # search the list of registered engines by name and return on first match
        for engine in engines:
            if engine['name'] == name:
                return True
        return False

    def __register_missing_ec2s(self):
        existing_engines = self.cxsast_api.get_engines()
        for ec2 in self.ec2_api.find_running_engines():
            if not self.__is_engine_registered(existing_engines, ec2.enginename):
                try:
                    url = ec2.uri + '/swagger/index.html'
                    self.logger.debug("GET %s" % url)
                    response = http.request('GET', url, retries=False, timeout=Timeout(1))
                    self.logger.debug(response)
                    if response.status == 200:
                        self.logger.debug("%s is online and will be registered." % ec2.enginename)
                        self.cxsast_api.register_engine(ec2.enginename, ec2.uri, ec2.max_scans, ec2.min_loc,
                                                        ec2.max_loc)
                    else:
                        self.logger.debug(
                            "Skipping registration of %s because the swagger page is not live yet" % ec2.enginename)
                except urllib3.exceptions.NewConnectionError:
                    self.logger.error('Error pinging swagger/index.html on %s' % ec2.enginename)


class TerminationProtectionManager:

    def __init__(self, cx_api, ec2_api):
        self.ec2_api = ec2_api
        self.cxsast_api = cx_api

    @staticmethod
    def __find_ec2_by_name(ec2s, name):
        for ec2 in ec2s:
            if ec2.instanceid == name:
                return ec2

    # Updates ASG instance protection for each SAST engine based on its status (scanning or idle)
    def update_instance_protection(self):
        ec2s = self.ec2_api.find_running_engines()
        for engine in self.cxsast_api.get_engines():
            ec2 = self.__find_ec2_by_name(ec2s, engine['name'])
            if ec2 is not None:
                if engine['status']['id'] == ENGINE_STATUS_SCANNING:
                    self.ec2_api.set_instance_protection(ec2, True)
                else:
                    self.ec2_api.set_instance_protection(ec2, False)


class QueueManager:

    def __init__(self, cx_api, ec2_api):
        self.cxsast_api = cx_api
        self.ec2_api = ec2_api

    def do_engine_registration(self):
        registrar = EngineRegistrar(self.cxsast_api, self.ec2_api)
        registrar.update()

    def do_instance_protection(self):
        protector = TerminationProtectionManager(self.cxsast_api, self.ec2_api)
        protector.update_instance_protection()

    def do_metrics(self):
        # Calculate the scan queue depth
        queue_depth_calculator = ScanQueueDepth(self.cxsast_api)
        queue_depth_calculator.calculate_queue_depth()

        # Publish scan queue depth metrics to cloudwatch
        metrics_publisher = ScanQueueDepthMetricsPublisher(queue_depth_calculator, os.environ['CheckmarxEnvironment'])
        metrics_publisher.publish()


class LifecycleEventReceiver:

    def __init__(self, event, cx_api):
        self.logger = logging.getLogger('LifecycleEventReceiver')
        self.cxsast_api = cx_api
        self.event = event
        self.message_id = event['Records'][0]['Sns']['MessageId']

        message = json.loads(event['Records'][0]['Sns']['Message'])
        self.instance_id = message['EC2InstanceId']

    def receive(self):
        self.logger.info("receiving event")
        self.__ensure_engine_is_blocked()
        self.__save_event()

    def __ensure_engine_is_blocked(self):
        self.logger.info("blocking engine")
        engine = self.cxsast_api.get_engine_by_name(self.instance_id)
        if engine is None:
            return

        status = engine['status']['id']
        if status != ENGINE_STATUS_SCANNINGANDBLOCKED and status != ENGINE_STATUS_BLOCKED:
            self.cxsast_api.update_engine(engine['id'],
                                          engine['name'],
                                          engine['uri'],
                                          engine['maxScans'],
                                          engine['minLoc'],
                                          engine['maxLoc'],
                                          True)

    def __save_event(self):
        logger.info("Putting message %s into dynamo" % self.message_id)
        client = boto3.client('dynamodb')
        response = client.put_item(
            TableName=os.environ['DynamoDbTableName'],
            Item={
                "MessageId": {"S": self.message_id},
                "Message": {"S": json.dumps(self.event)}
            }
        )
        logger.info(response)


class LifeCycleManager:

    def __init__(self, event, cx_api, ec2_api):
        self.logger = logging.getLogger('LifeCycleManager')
        self.logger.info(event)

        self.cxsast_api = cx_api
        self.ec2_api = ec2_api
        self.event = event
        message = json.loads(event['Records'][0]['Sns']['Message'])
        self.message_id = event['Records'][0]['Sns']['MessageId']
        self.instance_id = message['EC2InstanceId']

        self.lifecycle_hook_name = message['LifecycleHookName']
        self.instance_id = message['EC2InstanceId']
        self.lifecycle_action_token = message['LifecycleActionToken']
        self.autoscaling_group_name = message['AutoScalingGroupName']

    def __complete_lifecycle_hook(self):
        self.logger.debug('__complete_lifecycle_hook')
        self.logger.info('Completing lifecycle hook %s %s %s' % (
            self.lifecycle_hook_name, self.autoscaling_group_name, self.instance_id))
        client = boto3.client('autoscaling')
        try:
            response = client.complete_lifecycle_action(
                LifecycleHookName=self.lifecycle_hook_name,
                AutoScalingGroupName=self.autoscaling_group_name,
                LifecycleActionToken=self.lifecycle_action_token,
                LifecycleActionResult='CONTINUE',
                InstanceId=self.instance_id
            )
            self.logger.info(response)
        except ClientError as e:
            self.logger.exception(e)

        self.__delete_dynamo_event()

    def __delete_dynamo_event(self):
        self.logger.debug('__delete_dynamo_event')
        self.logger.info('deleting dynamodb event MessageId %s' % self.message_id)
        client = boto3.client('dynamodb')
        try:
            response = client.delete_item(
                TableName=os.environ['DynamoDbTableName'],
                Key={"MessageId": {"S": self.message_id}}
            )
            logger.info(response)
        except ClientError as e:
            logger.exception(e)

    def __record_lifecycle_action_heartbeat(self):
        self.logger.debug('__record_lifecycle_action_heartbeat')
        self.logger.info('Recording heartbeat for %s %s %s' % (
            self.lifecycle_hook_name, self.autoscaling_group_name, self.instance_id))

        client = boto3.client('autoscaling')
        client.record_lifecycle_action_heartbeat(
            LifecycleHookName=self.lifecycle_hook_name,
            AutoScalingGroupName=self.autoscaling_group_name,
            LifecycleActionToken=self.lifecycle_action_token,
            InstanceId=self.instance_id
        )

    def process(self):
        self.logger.debug('process')
        # Get the engine so we can process it
        engine = self.cxsast_api.get_engine_by_name(self.instance_id)
        # Immediately complete the hook when the engine is not registered and termination hook has been received
        if engine is None:
            logger.debug("No engine exists for name %s" % self.instance_id)
            self.__complete_lifecycle_hook()
            return  # nothing else to do in this scenario

        # ignore the engine in cx manager server
        if engine_in_manager_ip in engine['uri']:
            return

        status = int(engine['status']['id'])
        # Make sure the engine is blocked
        if status != ENGINE_STATUS_SCANNINGANDBLOCKED and status != ENGINE_STATUS_BLOCKED:
            self.cxsast_api.update_engine(engine['id'], engine['name'], engine['uri'], engine['maxScans'],
                                          engine['minLoc'], engine['maxLoc'], True)
        # When the engine is *not* scanning, then we can immediately unregister and complete the hook
        if status != ENGINE_STATUS_SCANNINGANDBLOCKED and status != ENGINE_STATUS_SCANNING:
            self.cxsast_api.unregister_engine(engine['id'])
            self.__complete_lifecycle_hook()
        # Otherwise the engine has a scan in progress, so issue heartbeat
        else:
            self.__record_lifecycle_action_heartbeat()


def lambda_handler(event, context):
    logger.info(event)
    ec2_api = Ec2Api(os.environ['CheckmarxEnvironment'])
    logger.info("Start processing event")
    cx_sast_api = CxSastRestApi()
    cx_sast_api.register_local_engine_if_missing(f"http://{engine_in_manager_ip}:8088")
    if 'Records' in event:
        logger.info('invoked from sns')
        receiver = LifecycleEventReceiver(event, cx_sast_api)
        receiver.receive()
    else:
        logger.info('invoked from schedule')
        manager = QueueManager(cx_sast_api, ec2_api)
        manager.do_metrics()
        manager.do_engine_registration()
        manager.do_instance_protection()

        dynamo = boto3.client('dynamodb')
        paginator = dynamo.get_paginator('scan')
        for page in paginator.paginate(TableName=os.environ['DynamoDbTableName']):
            logger.info("processing lifecycle hooks")
            for item in page['Items']:
                sns_event = json.loads(item['Message']['S'])
                lifecycle_manager = LifeCycleManager(sns_event, cx_sast_api, ec2_api)
                lifecycle_manager.process()

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps({
            "Region ": "ap-southeast-1"
        })
    }
