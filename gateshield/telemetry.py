"""Optional OpenTelemetry setup and privacy-safe stage spans."""

from __future__ import annotations

from contextlib import contextmanager
from importlib import import_module
from typing import Any, Iterator

from opentelemetry import propagate, trace


TRACER = trace.get_tracer("gateshield.gateway")


def configure_tracing(endpoint: str, service_name: str) -> Any | None:
    """Configure an OTLP/HTTP exporter. Observability dependencies are an optional extra."""
    if not isinstance(trace.get_tracer_provider(), trace.ProxyTracerProvider):
        # Let a host process that initialized OpenTelemetry own its exporter and lifecycle.
        return None
    try:
        exporter_module = import_module("opentelemetry.exporter.otlp.proto.http.trace_exporter")
        resources_module = import_module("opentelemetry.sdk.resources")
        trace_module = import_module("opentelemetry.sdk.trace")
        export_module = import_module("opentelemetry.sdk.trace.export")
    except ImportError as exc:
        raise RuntimeError(
            "Install GateShield with the observability extra to enable OTLP tracing"
        ) from exc

    provider = trace_module.TracerProvider(
        resource=resources_module.Resource.create({"service.name": service_name})
    )
    provider.add_span_processor(
        export_module.BatchSpanProcessor(exporter_module.OTLPSpanExporter(endpoint=endpoint))
    )
    trace.set_tracer_provider(provider)
    if trace.get_tracer_provider() is not provider:
        provider.shutdown()
        raise RuntimeError("Could not install the GateShield OpenTelemetry provider")
    return provider


@contextmanager
def stage_span(
    name: str, *, context: Any = None, **attributes: str | int | bool | None
) -> Iterator[Any]:
    """Create a span with only explicitly supplied, low-sensitivity attributes."""
    with TRACER.start_as_current_span(name, context=context) as span:
        for key, value in attributes.items():
            if value is not None:
                span.set_attribute(key, value)
        yield span


def parent_context(headers: Any) -> Any:
    """Extract W3C trace context from incoming headers."""
    return propagate.extract(headers)
