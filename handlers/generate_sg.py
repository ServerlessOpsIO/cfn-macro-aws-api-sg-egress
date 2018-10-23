'''Greate CFN SG rules from IP prefix list'''

import json
import logging
import os

from botocore.vendored import requests

log_level = os.environ.get('LOG_LEVEL', 'INFO')
logging.root.setLevel(logging.getLevelName(log_level))  # type: ignore
_logger = logging.getLogger(__name__)

AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

def _create_sg_rule(cidr: str) -> dict:
    '''Create an SG rule'''
    rule = {
        'CidrIp': cidr,
        'FromPort': -1,
        'ToPort': -1,
        'IpProtocol': "-1"
    }

    return rule


def _get_aws_cidrs(region: str, url=AWS_IP_RANGES_URL) -> list:
    '''Return list of '''
    r = requests.get(url)
    cidr_list = []
    for cidr in r.json().get('prefixes'):
        if cidr.get('region') == region:
            cidr_list.append(cidr.get('ip_prefix'))
    return cidr_list


def _get_region_from_event(event: dict) -> str:
    '''Return region from event'''
    return event.get('region')

def _get_vpc_id_from_event(event: dict) -> str:
    '''Return region from event'''
    return event.get('params').get('VpcId')


def _make_sg_resource(vpc_id: str, sg_rule_list: list) -> dict:
    '''Make SG resources'''
    template = {
        'Type': 'AWS::EC2::SecurityGroup',
        'Properties': {
            'VpcId': vpc_id,
            'GroupDescription': 'AWS API access',
            'SecurityGroupEgress': sg_rule_list
        }
    }

    return template


def handler(event, context):
    '''Function entry'''
    _logger.debug('Event received: {}'.format(json.dumps(event)))

    try:
        region = _get_region_from_event(event)
        vpc_id = _get_vpc_id_from_event(event)

        cidr_list = _get_aws_cidrs(region)
        sg_rule_list = []
        for cidr in cidr_list:
            sg_rule_list.append(_create_sg_rule(cidr))

        fragment = _make_sg_resource(vpc_id, sg_rule_list)

    except Exception as e:
        return {
            "requestId": event["requestId"],
            "status": "failure",
            "fragment": event["fragment"],
        }

    resp = {
        "requestId": event["requestId"],
        "status": "success",
        "fragment": fragment,
    }
    _logger.debug('Response: {}'.format(json.dumps(resp)))
    return resp

