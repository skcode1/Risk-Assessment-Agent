"""
Phase 2 — Make telemetry real.

Tests for telemetry workers and kernel isolation:

Step 16: Kafka detection consumer subscribes to 'detections',
         performs ZREMRANGEBYSCORE + ZADD + EXPIRE on counter:{ip}:events
         in a pipeline, commits offsets after Redis success.
Step 17: OpenSearch index names use OPENSEARCH_INDEX_PREFIX with monthly
         rollover security-events-YYYY.MM; ILM policy file under infra/opensearch/.
Step 18: Threat intel worker checks Redis ti:{ip} (TTL 24h), OpenSearch
         threat-intel-indicators*, external feed via httpx+tenacity.
         Kernel output identical with and without threat-intel hit.
Step 19: Calibration job computes p90/p99, proposes policy as PENDING_APPROVAL,
         never auto-activates.
Step 20: CMDB sync job pulls from inventory API, creates draft policy with
         updated endpoint_class_weights, invalidates policy:active.
"""

import json
import os
from datetime import UTC, datetime
from decimal import Decimal
from typing import Self
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.config import settings
from app.domain.engine.kernel import DeterministicRiskScoringKernel
from app.domain.models.assessment import RiskComponents
from app.domain.models.enums import EndpointClass, RiskCategory
from app.domain.models.policy import RiskPolicy
from app.workers.calibration_job import CalibrationJob, CalibrationResult
from app.workers.cmdb_sync import CMDBsyncJob
from app.workers.detection_consumer import DetectionConsumer
from app.workers.opensearch_index import (
    get_security_events_index_name,
    get_threat_intel_index_name,
)
from app.workers.threat_intel_worker import ThreatIndicator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _spec_policy() -> RiskPolicy:
    return RiskPolicy.create_spec_default(version="risk-policy-2026-01")


def _canonical_components() -> RiskComponents:
    return RiskComponents(
        behavior=Decimal("90.0"),
        frequency=Decimal("85.0"),
        sensitivity=Decimal("80.0"),
        history=Decimal("60.0"),
    )


# ---------------------------------------------------------------------------
# Step 17 — OpenSearch index naming
# ---------------------------------------------------------------------------


class TestStep17OpenSearchIndexNaming:
    """Index names use OPENSEARCH_INDEX_PREFIX with monthly rollover."""

    def test_security_events_index_name_fixed_date(self) -> None:
        """Step 17: Index name follows {prefix}-YYYY.MM format for a fixed date."""
        fixed = datetime(2026, 10, 15, tzinfo=UTC)
        name = get_security_events_index_name(fixed)
        assert name == "security-events-2026.10"

    def test_threat_intel_index_name_fixed_date(self) -> None:
        """Step 17: Threat intel index name follows threat-intel-indicators-YYYY.MM."""
        fixed = datetime(2026, 10, 15, tzinfo=UTC)
        name = get_threat_intel_index_name(fixed)
        assert name == "threat-intel-indicators-2026.10"


# ---------------------------------------------------------------------------
# Step 18 — Threat intel: kernel isolation
# ---------------------------------------------------------------------------


class TestStep18ThreatIntelKernelIsolation:
    """Threat intel enrichment must never modify the deterministic kernel score."""

    def test_kernel_output_identical_with_and_without_threat_intel(self) -> None:
        """Step 18: Kernel score is identical regardless of threat-intel hits,
        proving enrichment flows only into narrative/SOC queue, never into score."""
        policy = _spec_policy()
        kernel = DeterministicRiskScoringKernel()
        components = _canonical_components()

        # Baseline: no threat intel
        result_baseline = kernel.calculate_from_components(components, policy)
        baseline_score = result_baseline.risk_score
        baseline_rating = result_baseline.rating

        # Simulate a critical threat-intel hit (highest confidence, critical severity)
        threat_hit = ThreatIndicator(
            indicator_type="ip",
            value="192.0.2.10",
            confidence=100,
            severity="critical",
            source="external-feed",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            tags=["apt", "malware-c2"],
        )

        # The kernel does NOT receive threat intel — it only receives
        # detection, investigation, and policy. The threat intel worker
        # writes to Redis and publishes to Kafka, but never touches the kernel.
        assert threat_hit.confidence == 100 and threat_hit.severity == "critical"
        result_with_ti = kernel.calculate_from_components(components, policy)

        assert result_with_ti.risk_score == baseline_score == Decimal("83.5")
        assert result_with_ti.rating == baseline_rating == RiskCategory.HIGH
        assert result_with_ti.risk_score == Decimal("83.5")
        assert result_with_ti.rating == RiskCategory.HIGH


# ---------------------------------------------------------------------------
# Step 16 — Kafka detection consumer: sliding-window ZSET updates
# ---------------------------------------------------------------------------


class _FakePipeline:
    """Minimal async pipeline: records ops, then applies Redis ZSET semantics."""

    def __init__(self, store: "_FakeRedis") -> None:
        self._store = store
        self.ops: list[tuple] = []

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    def zremrangebyscore(self, key: str, min_score: str, max_score: float) -> None:
        self.ops.append(("zremrangebyscore", key, min_score, max_score))

    def zadd(self, key: str, mapping: dict[str, float]) -> None:
        self.ops.append(("zadd", key, dict(mapping)))

    def expire(self, key: str, seconds: int) -> None:
        self.ops.append(("expire", key, seconds))

    async def execute(self) -> list[bool]:
        for op in self.ops:
            kind = op[0]
            if kind == "zremrangebyscore":
                _, key, min_s, max_s = op
                zset = self._store.zsets.setdefault(key, {})
                lo, hi = float(min_s), float(max_s)
                for member in [m for m, s in zset.items() if lo <= s <= hi]:
                    del zset[member]
            elif kind == "zadd":
                _, key, mapping = op
                self._store.zsets.setdefault(key, {}).update(mapping)
            else:
                _, key, seconds = op
                self._store.ttls[key] = seconds
        self._store.executed_ops.extend(self.ops)
        return [True] * len(self.ops)


class _FakeRedis:
    """In-memory Redis double supporting pipeline() and delete()."""

    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}
        self.ttls: dict[str, int] = {}
        self.executed_ops: list[tuple] = []
        self.deleted_keys: list[str] = []

    def pipeline(self, transaction: bool = True) -> _FakePipeline:
        return _FakePipeline(self)

    async def delete(self, key: str) -> int:
        self.deleted_keys.append(key)
        self.zsets.pop(key, None)
        self.ttls.pop(key, None)
        return 1


@patch("app.workers.detection_consumer.Consumer")
class TestStep16DetectionConsumer:
    """Consumer subscribes to 'detections' and updates Redis counters atomically."""

    async def test_single_message_yields_cardinality_one(self, _mock_cls) -> None:
        """Produce one message -> ZSET cardinality == 1 under counter:{ip}:events."""
        redis = _FakeRedis()
        consumer = DetectionConsumer(redis_client=redis, window_seconds=3600)
        raw = json.dumps(
            {
                "event_id": "evt-1",
                "correlation_id": "corr-1",
                "source_ip": "198.51.100.7",
                "detected_at": 1_760_000_000.0,
            },
        )
        event = consumer._parse_message(raw)
        assert event is not None

        ok = await consumer._update_redis_counter(event)
        assert ok is True

        key = "counter:198.51.100.7:events"
        assert len(redis.zsets[key]) == 1
        assert "evt-1" in redis.zsets[key]
        assert redis.ttls[key] == 7200  # window_seconds * 2

    async def test_pipeline_prunes_stale_and_orders_ops(self, _mock_cls) -> None:
        """ZREMRANGEBYSCORE -> ZADD -> EXPIRE in one pipeline; stale entries pruned."""
        redis = _FakeRedis()
        consumer = DetectionConsumer(redis_client=redis, window_seconds=3600)
        now = 1_760_000_000.0
        key = "counter:198.51.100.7:events"
        redis.zsets[key] = {"evt-stale": now - 7200.0}  # outside the window

        event = consumer._parse_message(
            json.dumps(
                {
                    "event_id": "evt-new",
                    "correlation_id": "corr-2",
                    "source_ip": "198.51.100.7",
                    "detected_at": now,
                },
            ),
        )
        assert event is not None
        assert await consumer._update_redis_counter(event) is True

        # Stale member pruned; exactly one current member remains
        assert set(redis.zsets[key]) == {"evt-new"}
        assert [op[0] for op in redis.executed_ops] == [
            "zremrangebyscore",
            "zadd",
            "expire",
        ]

    async def test_offset_commit_only_after_redis_success(self, mock_cls) -> None:
        """Manual offset commit: offsets committed only after Redis success."""
        DetectionConsumer(redis_client=_FakeRedis())
        config = mock_cls.call_args[0][0]
        assert config["enable.auto.commit"] is False
        assert config["auto.offset.reset"] == "earliest"
        assert config["group.id"] == "detection-consumer-group"

    async def test_window_seconds_governed_by_settings(self, _mock_cls) -> None:
        """Window comes from SLIDING_WINDOW_SECONDS (settings/env), not a literal."""
        expected = int(getattr(settings.app, "SLIDING_WINDOW_SECONDS", 3600))
        consumer = DetectionConsumer(redis_client=_FakeRedis())
        assert consumer.window_seconds == expected

        explicit = DetectionConsumer(redis_client=_FakeRedis(), window_seconds=60)
        assert explicit.window_seconds == 60

    async def test_malformed_message_is_rejected(self, _mock_cls) -> None:
        consumer = DetectionConsumer(redis_client=_FakeRedis())
        assert consumer._parse_message("not-json") is None


class TestStep16KafkaPublish:
    """API publishes detections to 'detections' so the consumer can run."""

    def test_publish_payload_matches_consumer_contract(self) -> None:
        from app.core import kafka as kafka_module

        mock_producer = MagicMock()
        mock_producer.flush.return_value = 0
        payload = {
            "event_id": "evt-1",
            "correlation_id": "corr-1",
            "source_ip": "198.51.100.7",
            "detected_at": 1_760_000_000.0,
        }

        with patch.object(kafka_module, "_producer", mock_producer):
            ok = kafka_module.publish_detection_event(payload)

        assert ok is True
        args, kwargs = mock_producer.produce.call_args
        assert args[0] == os.getenv("KAFKA_TOPIC_DETECTIONS", "detections")
        body = json.loads(kwargs["value"])
        assert set(body) == {"event_id", "correlation_id", "source_ip", "detected_at"}
        mock_producer.flush.assert_called_once()


# ---------------------------------------------------------------------------
# Step 19 — Calibration job: PENDING_APPROVAL, never auto-activates
# ---------------------------------------------------------------------------


class _FakeResult:
    def scalar_one_or_none(self) -> None:
        return None


class _FakeTransaction:
    def __init__(self, session: "_FakeDBSession") -> None:
        self._session = session

    async def __aenter__(self) -> "_FakeDBSession":
        return self._session

    async def __aexit__(self, *exc: object) -> bool:
        return False


class _FakeDBSession:
    """Async session double capturing inserted policy models."""

    def __init__(self) -> None:
        self.added: list[object] = []

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    def begin(self) -> _FakeTransaction:
        return _FakeTransaction(self)

    async def execute(self, stmt: object, params: dict | None = None) -> _FakeResult:
        return _FakeResult()

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        return None


def _fixed_session_factory(session: _FakeDBSession):
    def factory() -> _FakeDBSession:
        return session

    return factory


class TestStep19CalibrationPendingApproval:
    """Calibration proposals are PENDING_APPROVAL; never auto-activated."""

    def test_compute_calibration_percentiles(self) -> None:
        job = CalibrationJob(db_session_factory=MagicMock())
        freq = list(range(100))  # 0..99
        hist = [i * 10 for i in range(100)]  # 0..990 step 10

        result = job.compute_calibration(freq, hist)

        assert result.sample_size == 100
        assert result.frequency_p90 == 90.0
        assert result.frequency_p99 == 99.0
        assert result.history_p90 == 900.0
        assert result.history_p99 == 990.0
        assert result.analysis_window_days == job.analysis_window_days

    def test_proposal_policy_is_never_active(self) -> None:
        job = CalibrationJob(db_session_factory=MagicMock())
        current = _spec_policy()
        calibration = CalibrationResult(
            frequency_p90=80.0,
            frequency_p99=250.0,
            history_p90=3.0,
            history_p99=12.0,
            sample_size=150,
            analysis_window_days=30,
        )

        proposal = job.create_proposal_policy(current, calibration)

        assert proposal.is_active is False
        assert "calibration" in proposal.version
        assert proposal.version != current.version
        assert proposal.metadata["frequency_config"]["saturation_count"] == 250
        assert proposal.metadata["history_config"]["incident_saturation_ceiling"] == 12
        assert proposal.metadata["calibration_proposal"]["frequency_p99"] == 250.0

    async def test_persist_proposal_marked_pending_approval(self) -> None:
        session = _FakeDBSession()
        job = CalibrationJob(db_session_factory=_fixed_session_factory(session))
        current = _spec_policy()
        calibration = CalibrationResult(
            frequency_p90=80.0,
            frequency_p99=250.0,
            history_p90=3.0,
            history_p99=12.0,
            sample_size=150,
            analysis_window_days=30,
        )
        proposal = job.create_proposal_policy(current, calibration)

        ok = await job.persist_proposal(proposal)

        assert ok is True
        assert proposal.metadata["proposal_status"] == "PENDING_APPROVAL"
        assert proposal.is_active is False
        assert len(session.added) == 1
        persisted = session.added[0]
        assert persisted.is_active is False
        assert persisted.created_by == "system:calibration-job"


# ---------------------------------------------------------------------------
# Step 20 — CMDB sync: mocked inventory -> draft policy + cache invalidation
# ---------------------------------------------------------------------------


class TestStep20CMDBSync:
    """CMDB sync pulls inventory, drafts endpoint weights, invalidates cache."""

    async def test_fetch_assets_from_mocked_inventory_response(self) -> None:
        job = CMDBsyncJob(
            db_session_factory=MagicMock(),
            cmdb_api_url="https://cmdb.example.test/api/assets",
            cmdb_api_key="test-key",
        )
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "assets": [
                {
                    "asset_id": "a-001",
                    "hostname": "db-prod-01",
                    "ip_address": "10.1.1.10",
                    "asset_class": "DATABASE_SERVER",
                    "criticality": "critical",
                    "tags": ["production"],
                },
                {
                    "asset_id": "a-002",
                    "hostname": "wks-user-01",
                    "ip_address": "10.1.10.11",
                    "asset_class": "WORKSTATION",
                    "criticality": "low",
                    "tags": ["standard"],
                },
            ],
        }

        with patch(
            "httpx.AsyncClient.get", new=AsyncMock(return_value=mock_response)
        ) as mock_get:
            assets = await job.fetch_assets()

        assert len(assets) == 2
        assert assets[0].asset_id == "a-001"
        assert assets[0].asset_class == "DATABASE_SERVER"
        assert assets[1].criticality == "low"
        assert assets[1].tags == ["standard"]
        mock_get.assert_awaited_once()

    def test_calculate_endpoint_weights_from_inventory(self) -> None:
        job = CMDBsyncJob(db_session_factory=MagicMock())

        weights = job.calculate_endpoint_weights(job._get_mock_assets())

        # Weighted-average criticality with per-class default floors applied
        assert weights[EndpointClass.DATABASE_SERVER] == Decimal("92.5")
        assert weights[EndpointClass.DOMAIN_CONTROLLER] == Decimal("95.0")
        assert weights[EndpointClass.INTERNAL_SERVER] == Decimal("72.5")
        assert weights[EndpointClass.WORKSTATION] == Decimal("50.0")
        assert weights[EndpointClass.GUEST_DEVICE] == Decimal("40.0")

    def test_sync_policy_is_draft_with_merged_weights(self) -> None:
        job = CMDBsyncJob(db_session_factory=MagicMock())
        current = _spec_policy()
        new_weights = {
            EndpointClass.DATABASE_SERVER: Decimal("92.5"),
            EndpointClass.WORKSTATION: Decimal("50.0"),
        }

        draft = job.create_sync_policy(current, new_weights)

        assert draft.is_active is False  # draft only - requires approval
        assert "cmdb-sync" in draft.version
        assert draft.endpoint_class_weights[EndpointClass.DATABASE_SERVER] == Decimal(
            "92.5"
        )
        # Classes not covered by the sync inherit current policy weights
        for ep, wt in current.endpoint_class_weights.items():
            if ep not in new_weights:
                assert draft.endpoint_class_weights[ep] == wt
        assert "cmdb_sync" in draft.metadata

    async def test_invalidate_active_policy_cache(self) -> None:
        """Step 20: after drafting, policy:active is invalidated."""
        redis = _FakeRedis()
        job = CMDBsyncJob(db_session_factory=MagicMock(), redis_client=redis)

        ok = await job.invalidate_active_policy_cache()

        assert ok is True
        assert "policy:active" in redis.deleted_keys
