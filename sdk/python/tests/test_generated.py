"""The generated stubs are committed, so they can drift from the .proto.

This asserts they exist and carry the shapes the SDK depends on. `make
proto-python` regenerating with no diff is the other half, enforced by the
Makefile target rather than here.
"""


def test_generated_stubs_are_importable_and_carry_the_expected_shapes():
    from stratium._pdp import pdp_pb2, pdp_pb2_grpc

    # DENY must be zero: an unset enum field decodes to it, which is what
    # makes a truncated or empty response fail closed.
    assert pdp_pb2.EFFECT_DENY == 0
    assert pdp_pb2.EFFECT_ALLOW == 1
    assert pdp_pb2.EFFECT_ESCALATE == 2

    assert hasattr(pdp_pb2_grpc, "PDPServiceStub")
    for field in ("agent_id", "subject", "tool", "raw_input", "token", "harness", "cwd"):
        assert field in pdp_pb2.DecideRequest.DESCRIPTOR.fields_by_name
    for field in ("effect", "reason", "approval_id", "epoch"):
        assert field in pdp_pb2.DecideResponse.DESCRIPTOR.fields_by_name
