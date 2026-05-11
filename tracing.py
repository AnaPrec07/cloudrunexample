from opentelemetry import trace
from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from config import GCP_PROJECT

# BatchSpanProcessor queues spans in memory and flushes in batches (default: 512
# spans or 5 seconds). force_flush() in the SIGTERM handler drains the queue
# before Cloud Run kills the container.
_tracer_provider = TracerProvider()
_tracer_provider.add_span_processor(
    BatchSpanProcessor(CloudTraceSpanExporter(project_id=GCP_PROJECT))
)
trace.set_tracer_provider(_tracer_provider)
tracer = trace.get_tracer(__name__)


def force_flush(timeout_millis: int = 5000) -> None:
    _tracer_provider.force_flush(timeout_millis=timeout_millis)


def shutdown() -> None:
    _tracer_provider.shutdown()
