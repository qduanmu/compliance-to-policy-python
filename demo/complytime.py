# Copyright (c) 2024 Red Hat, Inc.
# SPDX-License-Identifier: Apache-2.0


"""
Run C2P with the OpenSCAP plugin
"""

import logging
import os
import subprocess
import time

import grpc

from c2p.framework.c2p import C2P  # type: ignore
from c2p.framework.models.c2p_config import C2PConfig, ComplianceOscal  # type: ignore
import c2p.framework.api.proto.policy_pb2_grpc as pb2_grpc  # type: ignore
import c2p.framework.api.proto.policy_pb2 as policy_pb2  # type: ignore
import c2p.framework.api.proto.models_pb2 as models_pb2  # type: ignore


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class ComplyTimeClient:
    """
    ComplyTime is an implementation of the compliance to policy.
    """

    def __init__(
        self,
        address: str,
        component_definition: str = "demo/component-definition.json"
    ):
        """
        Parameters
        ----------
        component_definition : string
            Location of the product component definition to evaluate
        """
        self.component_definition = component_definition
        self.address = address

    def _start_process(self) -> subprocess.Popen:
        try:
            command = "python plugins_public/plugins/auditree.py"
            environment = os.environ.copy()
            environment["UDS_ADDRESS"] = self.address
            process = subprocess.Popen(command, shell=True, env=environment)
            logging.info(f"Process started with PID: {process.pid}")
            time.sleep(5)
            return process
        except subprocess.CalledProcessError as e:
            logging.error(f"Error starting process: {e}")
            return None

    def _kill_process(self, process: subprocess.Popen):
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                process.wait()
                logging.info("Process terminated successfully.")
            except subprocess.TimeoutExpired:
                logging.warning("Process termination timed out.")
                process.kill()
        else:
            logging.info("Process is already terminated or not running.")

    def generate(self) -> None:
        """
        Generate some policy and stuff
        """
        try:
            c2p_config = self._create_c2p_config()
            c2p = C2P(c2p_config)
            rules: List[Rule] = []

            process = self._start_process()
            policy = c2p.get_policy()
            for r in policy.rule_sets:
                rule = models_pb2.Rule(
                    name=r.rule_id,
                    description=r.rule_description,
                )
                check = models_pb2.Check(
                    name=r.check_id,
                    description=r.check_description,
                )
                rule.checks.append(check)
                rules.append(rule)

            req = policy_pb2.PolicyRequest(rule=rules)
            with grpc.insecure_channel(self.address) as channel:
                stub = pb2_grpc.PolicyEngineStub(channel)
                # resp: policy_pb2.GenerateResponse = stub.Generate(req)
                stub.Generate(req)
        finally:
            self._kill_process(process)

    def get_results(self) -> None:
        """Get pvp result."""
        try:
            process = self._start_process()
            c2p_config = self._create_c2p_config()
            c2p = C2P(c2p_config)

            req = policy_pb2.PolicyRequest()
            with grpc.insecure_channel(self.address) as channel:
                stub = pb2_grpc.PolicyEngineStub(channel)
                resp: policy_pb2.ResultsResponse = stub.GetResults(req)
                print(resp.result)
                c2p.set_pvp_result(resp.result)
        finally:
            self._kill_process(process)

    def _create_c2p_config(self) -> C2PConfig:
        c2p_config = C2PConfig()
        c2p_config.compliance = ComplianceOscal()
        c2p_config.pvp_name = "Auditree"
        c2p_config.result_title = 'Auditree Assessment Results'
        c2p_config.result_description = 'OSCAL Assessment Results from Auditree'
        c2p_config.compliance.component_definition = self.component_definition
        return c2p_config


if __name__ == "__main__":
    uds_address = os.environ.get("UDS_ADDRESS")
    c = ComplyTimeClient(uds_address)  
    c.generate()
    c.get_results()
