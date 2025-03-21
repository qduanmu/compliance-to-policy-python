# -*- mode:python; coding:utf-8 -*-

# Copyright 2024 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import grpc
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import yaml
from concurrent import futures
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple, Union

from pydantic.v1 import Field
from pydantic.v1.utils import deep_update

from c2p.common.logging import getLogger
from c2p.common.utils import get_dict_safely
from c2p.framework.models import RawResult
from c2p.framework.plugin_spec import PluginConfig, PluginSpec
import c2p.framework.api.proto.policy_pb2_grpc as pb2_grpc
import c2p.framework.api.proto.policy_pb2 as policy_pb2
from c2p.framework.api.proto.models_pb2 import (
    Link,
    ObservationByCheck,
    Result,
    PVPResult,
    Subject,
)
from grpc_health.v1.health import HealthServicer
from grpc_health.v1 import health_pb2, health_pb2_grpc


logger = getLogger(__name__)

status_dictionary = {
    'pass': Result.RESULT_PASS,
    'fail': Result.RESULT_FAILURE,
    'warn': Result.RESULT_FAILURE,
    'error': Result.RESULT_ERROR,
}


def update_dict(d, key: Union[str, List[str]], value):
    if isinstance(key, str):
        data = copy.deepcopy(d)
        data[key] = value
        return data
    else:
        update = {key.pop(): value}
        for _key in reversed(key):
            update = {_key: update}
        return deep_update(d, update)


class PluginConfigAuditree(PluginConfig):
    auditree_json_template: str = Field(..., title='Path to auditree.json template')
    output: str = Field('auditree.json', title='Path to the generated auditree.json (default: ./auditree.json)')


class PluginAuditree(PluginSpec):

    def __init__(self, config: Optional[PluginConfigAuditree] = None) -> None:
        super().__init__()
        self.config = config

    def generate_pvp_policy(self, policy: policy_pb2.PolicyRequest):
        with Path(self.config.auditree_json_template).open('r') as f:
            auditree_json = json.load(f)
        for rule in policy.rule:
            parameter = rule.parameter
            if parameter:
                key = parameter.name
                value = get_dict_safely(auditree_json, key.split('.'))
                if value is not None:
                    try:
                        if isinstance(value, list):
                            updated = parameter.selected_value.split(',')
                        elif isinstance(value, str):
                            updated = parameter.selected_value
                        elif isinstance(value, int):
                            updated = int(parameter.selected_value)
                        elif isinstance(value, float):
                            updated = float(parameter.selected_value)
                        else:
                            raise Exception(f'Unsupported parameter value format (parameter_id: {key})')
                    except Exception as e:
                        raise Exception(f'Invalid parameter value format (parameter_id: {key})') from e
                    auditree_json = update_dict(auditree_json, key.split('.'), updated)
        json.dump(auditree_json, Path(self.config.output).open('w'), indent=2)

    def generate_pvp_result(self, raw_result: RawResult) -> PVPResult:
        locker_url = get_dict_safely(raw_result.additional_props, 'locker_url', 'files:///tmp/compliance')
        pvp_result: PVPResult = PVPResult()
        observations: List[ObservationByCheck] = []
        for check_class_name, check_class_result in raw_result.data.items():
            for check_method_name, check_method_result in get_dict_safely(check_class_result, 'checks', []).items():
                check_id = f'{check_class_name}.{check_method_name}'
                timestamp = get_dict_safely(check_method_result, 'timestamp')
                dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)

                observation = ObservationByCheck(
                    check_id=check_id,
                    methods=['AUTOMATED'],
                    collected_at=dt,
                )

                evidences = get_dict_safely(check_class_result, 'evidence', [])
                relevant_evidences = []
                for evidence in evidences:
                    href = f'{locker_url}/{get_dict_safely(evidence, "path", "")}'
                    description = get_dict_safely(evidence, 'description', '')
                    relevant_evidences.append(Link(description=description, href=href))

                status = get_dict_safely(check_method_result, 'status', 'not_found')
                if status is None:
                    reason = f'Status not found for this check {check_id}.'
                    status = ResultEnum.Error

                def generate_reason(status) -> str:
                    successes = get_dict_safely(check_method_result, 'successes', {})
                    warnings = get_dict_safely(check_method_result, 'warnings', {})
                    failures = get_dict_safely(check_method_result, 'failures', {})
                    exception = get_dict_safely(check_method_result, 'exception', {})
                    res = {}
                    if status == 'pass':
                        res = successes
                    elif status == 'warn':
                        res = warnings
                    elif status == 'fail':
                        res = failures
                    elif status == 'error':
                        res = exception
                    else:
                        res = successes
                        res.update(warnings)
                        res.update(failures)
                        res.update({'exception': exception} if exception != '' else {})
                    return f'{res}'

                subject = Subject(
                    title=f'Auditree Check: {check_id}',
                    type='inventory-item',
                    result=status_dictionary[status] if status in status_dictionary else Result.RESULT_ERROR,
                    resource_id=check_id,
                    evaluated_on=dt,
                    reason=generate_reason(status),
                )
                observation.subjects.append(subject)
                observations.append(observation)

        # merge observations whose check id is generated by parametrized expansion (see parameterized.expand())
        merged_observations: List[ObservationByCheck] = []
        merged_list: List[Tuple[str, ObservationByCheck]] = []

        for observation in observations:
            *classname, parametrized_method = observation.check_id.split('.')
            res = re.search('(.*)_([0-9]+)_(.+)$', parametrized_method)
            if res is not None:
                method = res.group(1)
                normalized_check_id = '.'.join(classname + [method])
                merged_list.append((normalized_check_id, observation))
            else:
                merged_observations.append(observation)

        for normalized_check_id in set([x[0] for x in merged_list]):
            group = [x[1] for x in merged_list if x[0] == normalized_check_id]
            merged_subjects = [subject for x in group for subject in x.subjects]
            observation = ObservationByCheck(
                check_id=normalized_check_id,
                methods=['AUTOMATED'],
                collected_at=group[0].collected_at,
                subjects=merged_subjects,
            )
            merged_observations.append(observation)

        pvp_result.observations.extend(merged_observations)

        return pvp_result


class AuditreeServicer(pb2_grpc.PolicyEngineServicer):
    """Implementation of Auditree service."""

    def __init__(self):
        self.config: Dict = {}
        self.plugin_id = "Auditree"

    def Generate(
        self, request: policy_pb2.PolicyRequest, context
    ) -> policy_pb2.GenerateResponse:
        """Implemented Generate"""
        auditree_template = "demo/auditree.template.json"
        tempdir = tempfile.mkdtemp(prefix="auditree_")
        generated_auditree_json = os.path.join(tempdir, 'auditree.json')
        config = PluginConfigAuditree(
            auditree_json_template=auditree_template, output=generated_auditree_json
        )
        generator = PluginAuditree(config)
        generator.generate_pvp_policy(request)
        return policy_pb2.GenerateResponse()

    def GetResults(
        self, request: policy_pb2.PolicyRequest, context
    ) -> policy_pb2.ResultsResponse:
        """Implemented GetResults."""

        # Here to run Auditree fetch and check using the auditree config created
        # in the Generate() step and get the check result in check_results.json.
        # Example:
        # $ compliance --fetch --evidence local -C auditree.json -v
        # $ compliance --check demo.arboretum.accred,demo.custom.accred --evidence local -C auditree.json -v
        tmp_path = "/tmp"
        auditree_json = ""
        for d in os.listdir(tmp_path):
            if d.startswith('auditree'):
                auditree_json = os.path.join(tmp_path, d, "auditree.json")
                break
        if not os.path.isfile(auditree_json):
            return policy_pb2.ResultsResponse()

        command_fetch = [
                "compliance",
                "--fetch",
                "--evidence",
                "local",
                "-C",
                auditree_json,
        ]
        subprocess.run(command_fetch, cwd='demo')

        # locker and result are in /tmp/compliance
        command_check = [
                "compliance",
                "--check",
                "demo.arboretum.accred,demo.custom.accred",
                "--evidence",
                "local",
                "-C",
                auditree_json,
        ]
        subprocess.run(command_check, cwd='demo')
        shutil.rmtree(os.path.dirname(auditree_json), ignore_errors=True)
        check_results_file = '/tmp/compliance/check_results.json'
        if not os.path.exists(check_results_file):
            return policy_pb2.ResultsResponse()
        check_results = yaml.safe_load(Path(check_results_file).open('r'))
        pvp_raw_result = RawResult(
            data=check_results,
            additional_props={
                'locker_url': 'https://github.com/MY_ORG/MY_EVIDENCE_REPO',
            },
        )
        pvp_result = PluginAuditree().generate_pvp_result(pvp_raw_result)
        return policy_pb2.ResultsResponse(result=pvp_result)


def serve(uds_address):
    # Build a health service to work with the plugin
    health = HealthServicer()
    health.set("plugin", health_pb2.HealthCheckResponse.ServingStatus.Value('SERVING'))

    server = grpc.server(futures.ThreadPoolExecutor())
    pb2_grpc.add_PolicyEngineServicer_to_server(AuditreeServicer(), server)
    health_pb2_grpc.add_HealthServicer_to_server(health, server)
    # Listen on a port
    server.add_insecure_port(uds_address)
    server.start()

    # Output information
    handshake_info = f"1|0.5.0|tcp|{uds_address}|grpc"
    # Output the handshake information to stdout, this is required for go-plugin.
    # go-plugin reads a single line from stdout to determine how to connect to the plugin.
    print(handshake_info)
    sys.stdout.flush()

    server.wait_for_termination()


if __name__ == "__main__":
    uds_address = os.environ.get("UDS_ADDRESS")
    serve(uds_address)
