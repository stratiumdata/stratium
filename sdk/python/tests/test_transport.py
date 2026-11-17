import shutil
import subprocess
from concurrent import futures

import grpc
import pytest

from stratium import Client, Effect
from stratium._pdp import pdp_pb2, pdp_pb2_grpc

from conftest import FakePDP


def test_tls_is_the_default_and_fails_closed_against_plaintext(fake_pdp):
    fake_pdp.decide_responses.append(pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW))
    with Client(fake_pdp.addr, connect_timeout=2.0) as c:
        d = c.decide(agent_id="a", subject="s", tool="Read", raw_input={}, token="t")
    assert not d
    assert d.effect is not Effect.ALLOW
    assert fake_pdp.decide_calls == []


def test_insecure_and_ca_file_conflict():
    with pytest.raises(ValueError, match="conflicts"):
        Client("127.0.0.1:1", insecure=True, ca_file="/ca.pem")


def test_missing_ca_file_raises_at_construction(tmp_path):
    with pytest.raises(OSError):
        Client("127.0.0.1:1", ca_file=str(tmp_path / "nope.pem"))


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl to mint a test certificate")
def test_tls_round_trip_with_private_ca(tmp_path):
    key, crt = tmp_path / "pdp.key", tmp_path / "pdp.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-keyout", str(key), "-out", str(crt), "-days", "1",
         "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
        check=True, capture_output=True,
    )
    servicer = FakePDP()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    pdp_pb2_grpc.add_PDPServiceServicer_to_server(servicer, server)
    creds = grpc.ssl_server_credentials([(key.read_bytes(), crt.read_bytes())])
    port = server.add_secure_port("127.0.0.1:0", creds)
    server.start()
    try:
        servicer.decide_responses.append(pdp_pb2.DecideResponse(effect=pdp_pb2.EFFECT_ALLOW))
        with Client(f"localhost:{port}", ca_file=str(crt)) as c:
            d = c.decide(agent_id="a", subject="s", tool="Read", raw_input={}, token="t")
        assert d
        assert len(servicer.decide_calls) == 1
    finally:
        server.stop(None)
