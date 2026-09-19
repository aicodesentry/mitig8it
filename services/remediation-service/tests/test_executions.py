from src.executions import PostgresExecutionBackend
from src.models import RepairRequest


def test_execution_identity_is_fence_and_content_bound(request_payload):
    request = RepairRequest.model_validate(request_payload)
    first = PostgresExecutionBackend.execution_identity(request)
    assert first == PostgresExecutionBackend.execution_identity(request)
    changed = request.model_copy(deep=True)
    changed.fencing_token += 1
    assert PostgresExecutionBackend.execution_identity(changed)[0] != first[0]
    changed = request.model_copy(deep=True)
    changed.files[0].content += "// changed\n"
    assert PostgresExecutionBackend.execution_identity(changed)[0] != first[0]
