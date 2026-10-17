"""
Core OpenTelemetry Instrumentation and Observability Module.
Configures distributed tracing, metric instrumentation, span processors,
and FastAPI auto-instrumentation without hardcoded parameters.
"""

from collections.abc import Mapping
import logging
from typing import Any, Optional

from fastapi import FastAPI
from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.semconv.resource import ResourceAttributes
from opentelemetry.trace import Tracer

from app.core.config import settings

logger = logging.getLogger(__name__)

# Tracer and Meter module-level handles
_tracer: Optional[Tracer] = None
_meter: Optional[metrics.Meter] = None


def build_resource(
    service_name: Optional[str] = None,
    environment: Optional[str] = None,
    extra_attributes: Optional[Mapping[str, Any]] = None,
) -> Resource:
    """
    Constructs an OpenTelemetry Resource descriptor capturing service identity,
    deployment tier, and telemetry attributes dynamically.
    """
    attrs: dict[str, Any] = {
        ResourceAttributes.SERVICE_NAME: service_name or settings.app.PROJECT_NAME,
        ResourceAttributes.DEPLOYMENT_ENVIRONMENT: environment or settings.app.ENVIRONMENT,
    }
    if extra_attributes:
        attrs.update(dict(extra_attributes))

    return Resource.create(attrs)


def setup_telemetry(
    app: Optional[FastAPI] = None,
    otlp_endpoint: Optional[str] = None,
    enable_console_fallback: bool = False,
) -> None:
    """
    Initializes OpenTelemetry TracerProvider, MeterProvider, and BatchSpanProcessors.
    Binds auto-instrumentation hooks to the FastAPI application instance if provided.
    """
    global _tracer, _meter

    resource = build_resource()

    # --- Tracing Configuration ---
    tracer_provider = TracerProvider(resource=resource)

    if otlp_endpoint:
        otlp_trace_exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        span_processor = BatchSpanProcessor(otlp_trace_exporter)
        tracer_provider.add_span_processor(span_processor)
        logger.info("Configured OTLP Span Exporter targeting %s", otlp_endpoint)
    elif enable_console_fallback or settings.app.DEBUG:
        console_exporter = ConsoleSpanExporter()
        tracer_provider.add_span_processor(BatchSpanProcessor(console_exporter))
        logger.debug("Configured Console Span Exporter for debug telemetry.")

    trace.set_tracer_provider(tracer_provider)
    _tracer = trace.get_tracer(
        instrumenting_module_name="app.domain.engine",
        instrumenting_library_version="1.0.0",
    )

    # --- Metrics Configuration ---
    metric_readers = []
    if otlp_endpoint:
        otlp_metric_exporter = OTLPMetricExporter(endpoint=otlp_endpoint, insecure=True)
        reader = PeriodicExportingMetricReader(
            exporter=otlp_metric_exporter,
            export_interval_millis=15000,
        )
        metric_readers.append(reader)

    meter_provider = MeterProvider(resource=resource, metric_readers=metric_readers)
    metrics.set_meter_provider(meter_provider)
    _meter = metrics.get_meter(
        name="app.risk.assessment",
        version="1.0.0",
    )

    # --- FastAPI Auto-Instrumentation ---
    if app is not None:
        FastAPIInstrumentor.instrument_app(
            app=app,
            tracer_provider=tracer_provider,
            meter_provider=meter_provider,
            excluded_urls="healthz,metrics,ready",
        )
        logger.info("FastAPI application instrumented with OpenTelemetry hooks.")


def get_tracer() -> Tracer:
    """Returns the configured global OpenTelemetry tracer."""
    global _tracer
    if _tracer is None:
        _tracer = trace.get_tracer("app.domain.engine")
    return _tracer


def get_meter() -> metrics.Meter:
    """Returns the configured global OpenTelemetry meter."""
    global _meter
    if _meter is None:
        _meter = metrics.get_meter("app.risk.assessment")
    return _meter


class TelemetryMetricsRegistry:
    """
    Central registry for scoring-kernel and ingestion performance counters,
    histograms, and gauge meters.
    """

    def __init__(self, meter: Optional[metrics.Meter] = None) -> None:
        self._meter = meter or get_meter()

        self.risk_assessment_counter = self._meter.create_counter(
            name="risk_evaluations_total",
            description="Total count of deterministic risk scoring calculations executed",
            unit="1",
        )

        self.scoring_duration_histogram = self._meter.create_histogram(
            name="scoring_duration_milliseconds",
            description="End-to-end duration of the risk scoring pipeline in milliseconds",
            unit="ms",
        )

        self.category_distribution_counter = self._meter.create_counter(
            name="risk_category_assignments_total",
            description="Distribution of resolved categories across evaluations",
            unit="1",
        )

        self.guardrail_violations_counter = self._meter.create_counter(
            name="guardrail_violations_total",
            description="Count of blocked LLM tampering attempts and injection events",
            unit="1",
        )


# Global metrics registry instance
telemetry_metrics = TelemetryMetricsRegistry()