from concurrent import futures

import grpc
import pytest

from stratium._pdp import pdp_pb2, pdp_pb2_grpc


class FakePDP(pdp_pb2_grpc.PDPServiceServicer):
    """Serves scripted responses and counts calls.

    The call count is what proves a cache was used: a second decide() that
    does not increment it was served locally.
    """

    def __init__(self):
        self.decide_responses: list = []
        self.delegation_responses: list = []
        self.approval_responses: list = []
        self.decide_calls: list = []
        self.approval_calls: list = []
        self.delegation_calls: list = []

    def Decide(self, request, context):
        self.decide_calls.append(request)
        if not self.decide_responses:
            context.abort(grpc.StatusCode.INTERNAL, "no scripted response")
        nxt = self.decide_responses.pop(0)
        return nxt(request) if callable(nxt) else nxt

    def CreateDelegation(self, request, context):
        self.delegation_calls.append(request)
        if not self.delegation_responses:
            context.abort(grpc.StatusCode.INTERNAL, "no scripted response")
        return self.delegation_responses.pop(0)

    def GetApproval(self, request, context):
        self.approval_calls.append(request)
        return self.approval_responses.pop(0)


@pytest.fixture
def fake_pdp():
    servicer = FakePDP()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    pdp_pb2_grpc.add_PDPServiceServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    servicer.addr = f"127.0.0.1:{port}"
    yield servicer
    server.stop(None)
