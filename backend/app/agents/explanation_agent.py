"""
Explainable AI (XAI) Narrative Agent Execution Engine.
Orchestrates prompt assembly via Jinja2 templates, executes LLM completions
(supporting OpenAI and Anthropic providers), enforces strict output guardrails
against deterministic score mutation, and stores verified explanations in PostgreSQL.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import time
from typing import Any, Dict, Optional, Tuple
from uuid import UUID, uuid4

import jinja2
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.enrichment_agent import (
    EnrichedContextBundle,
    TelemetryEnrichmentAgent,
)
from app.agents.guardrails import (
    GuardrailEvaluationResult,
    LLMGuardrailEnforcer,
)
from app.core.config import settings
from app.core.exceptions import (
    AssessmentNotFoundException,
    BaseAppException,
    LLMGuardrailViolationException,
)
from app.core.telemetry import get_tracer, telemetry_metrics
from app.db.models.explanation import RiskExplanationModel
from app.domain.models.enums import ComponentDriver, ExplanationSource
from app.schemas.explanation import ExplanationResponse

logger = logging.getLogger(__name__)
tracer = get_tracer()


class ExplanationGenerationException(BaseAppException):
    """Raised when the LLM provider fails to generate an explanation."""

    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(
            message=message,
            error_code="EXPLANATION_GENERATION_FAILED",
            status_code=502,
            context=context,
        )


class ExplanationAgent:
    """
    Executes constrained LLM reasoning to explain deterministic risk evaluations.
    Maintains zero score-mutation tolerance through post-generation guardrail enforcement.
    """

    def __init__(
        self,
        db_session: AsyncSession,
        enrichment_agent: Optional[TelemetryEnrichmentAgent] = None,
        guardrail_enforcer: Optional[LLMGuardrailEnforcer] = None,
        template_name: str = "xai_narrative.j2",
    ) -> None:
        self.db = db_session
        self.enrichment_agent = enrichment_agent or TelemetryEnrichmentAgent(db_session=db_session)
        self.guardrails = guardrail_enforcer or LLMGuardrailEnforcer()

        # Locate and configure Jinja2 template environment
        template_dir = Path(__file__).resolve().parent
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.template = self.jinja_env.get_template(template_name)

    async def generate_explanation(
        self,
        assessment_id: UUID,
        force_regenerate: bool = False,
    ) -> ExplanationResponse:
        """
        Coordinates full explanation lifecycle:
          1. Checks PostgreSQL for existing cached explanation.
          2. Pulls immutable assessment and enriched telemetry context.
          3. Renders prompt via Jinja2.
          4. Invokes LLM provider (Anthropic or OpenAI).
          5. Verifies output against deterministic invariants using LLMGuardrailEnforcer.
          6. Persists audit records to database.
        """
        start_time = time.perf_counter()

        with tracer.start_as_current_span("explanation_agent.generate_explanation") as span:
            span.set_attribute("assessment_id", str(assessment_id))

            # 1. Check existing record
            if not force_regenerate:
                existing_stmt = select(RiskExplanationModel).where(
                    RiskExplanationModel.assessment_id == assessment_id
                )
                existing_res = await self.db.execute(existing_stmt)
                existing_record = existing_res.scalars().first()
                if existing_record:
                    return ExplanationResponse.model_validate(existing_record)

            # 2. Enrich context bundle
            context_bundle: EnrichedContextBundle = (
                await self.enrichment_agent.build_context_bundle(assessment_id=assessment_id)
            )

            # 3. Render prompt
            prompt_payload = self._render_prompt(context_bundle)

            # 4. Invoke LLM provider
            model_id, raw_completion = await self._call_llm(prompt_payload)
            execution_duration_ms = (time.perf_counter() - start_time) * 1000.0

            # 5. Guardrail verification
            guardrail_result: GuardrailEvaluationResult = self.guardrails.verify(
                raw_response=raw_completion,
                baseline_score=context_bundle.assessment["risk_score"],
                baseline_rating=context_bundle.assessment["rating"],
            )

            if not guardrail_result.passed:
                telemetry_metrics.guardrail_violations_counter.add(
                    1, {"reason": guardrail_result.violation_reason or "UNKNOWN"}
                )
                logger.error(
                    "LLM Explanation violated guardrails for assessment %s: %s",
                    assessment_id,
                    guardrail_result.violation_reason,
                )
                raise LLMGuardrailViolationException(
                    rule_name="DETERMINISTIC_INVARIANCE_BREACH",
                    message=f"LLM explanation output rejected: {guardrail_result.violation_reason}",
                    context={
                        "assessment_id": str(assessment_id),
                        "raw_completion": raw_completion,
                        "guardrail_checks": guardrail_result.checks_evaluated,
                    },
                )

            parsed_data = guardrail_result.parsed_payload or {}

            # 6. Upsert explanation record in PostgreSQL
            explanation_model = await self._persist_explanation(
                assessment_id=assessment_id,
                parsed_data=parsed_data,
                model_identifier=model_id,
                guardrail_result=guardrail_result,
                duration_ms=execution_duration_ms,
            )

            return ExplanationResponse.model_validate(explanation_model)

    def _render_prompt(self, context_bundle: EnrichedContextBundle) -> str:
        """Renders the strict Jinja2 template with immutable inputs."""
        return self.template.render(
            assessment=context_bundle.assessment,
            detection=context_bundle.detection,
            investigation=context_bundle.investigation,
            override_record=context_bundle.analyst_override,
            threat_intel=context_bundle.threat_intel_summary,
        )

    async def _call_llm(self, prompt: str) -> Tuple[str, str]:
        """
        Dispatches prompt completion request to the active LLM provider
        configured in application settings (Anthropic / OpenAI).
        """
        provider = settings.llm.LLM_PROVIDER.lower()

        if provider == "anthropic":
            return await self._call_anthropic(prompt)
        elif provider == "openai":
            return await self._call_openai(prompt)
        else:
            raise ExplanationGenerationException(
                message=f"Unsupported LLM provider configured: '{settings.llm.LLM_PROVIDER}'."
            )

    async def _call_anthropic(self, prompt: str) -> Tuple[str, str]:
        """Executes Anthropic API completion."""
        try:
            import anthropic

            client = anthropic.AsyncAnthropic(
                api_key=settings.llm.ANTHROPIC_API_KEY.get_secret_value()
            )
            model_id = settings.llm.ANTHROPIC_MODEL

            message = await client.messages.create(
                model=model_id,
                max_tokens=settings.llm.MAX_TOKENS,
                temperature=settings.llm.TEMPERATURE,
                system="You are an explainable AI system that outputs strictly raw JSON adhering to provided schemas.",
                messages=[{"role": "user", "content": prompt}],
            )
            completion_text = message.content[0].text
            return model_id, completion_text

        except Exception as exc:
            logger.critical("Anthropic LLM call failed: %s", exc, exc_info=True)
            raise ExplanationGenerationException(
                message="Upstream Anthropic API call failed.",
                context={"error": str(exc)},
            ) from exc

    async def _call_openai(self, prompt: str) -> Tuple[str, str]:
        """Executes OpenAI API completion with JSON mode enforcement."""
        try:
            from openai import AsyncOpenAI

            client = AsyncOpenAI(
                api_key=settings.llm.OPENAI_API_KEY.get_secret_value()
            )
            model_id = settings.llm.OPENAI_MODEL

            response = await client.chat.completions.create(
                model=model_id,
                temperature=settings.llm.TEMPERATURE,
                max_tokens=settings.llm.MAX_TOKENS,
                response_format={"type": "json_object"},
                messages=[
                    {
                        "role": "system",
                        "content": "You are a deterministic cybersecurity XAI narrator that outputs only valid JSON.",
                    },
                    {"role": "user", "content": prompt},
                ],
            )
            completion_text = response.choices[0].message.content or ""
            return model_id, completion_text

        except Exception as exc:
            logger.critical("OpenAI LLM call failed: %s", exc, exc_info=True)
            raise ExplanationGenerationException(
                message="Upstream OpenAI API call failed.",
                context={"error": str(exc)},
            ) from exc

    async def _persist_explanation(
        self,
        assessment_id: UUID,
        parsed_data: Dict[str, Any],
        model_identifier: str,
        guardrail_result: GuardrailEvaluationResult,
        duration_ms: float,
    ) -> RiskExplanationModel:
        """Atomically saves or updates the verified RiskExplanationModel."""
        # Check if record already exists
        stmt = select(RiskExplanationModel).where(
            RiskExplanationModel.assessment_id == assessment_id
        )
        res = await self.db.execute(stmt)
        record = res.scalars().first()

        raw_driver = parsed_data.get("primary_driver", "BEHAVIOR").upper()
        try:
            primary_driver = ComponentDriver(raw_driver)
        except ValueError:
            primary_driver = ComponentDriver.BEHAVIOR

        summary_narrative = parsed_data.get("summary_narrative", "")
        key_factors = parsed_data.get("key_factors", [])
        evidence_citations = parsed_data.get("evidence_citations", [])

        metadata = {
            "execution_duration_ms": duration_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if record is None:
            record = RiskExplanationModel(
                explanation_id=uuid4(),
                assessment_id=assessment_id,
                summary_narrative=summary_narrative,
                primary_driver=primary_driver,
                key_factors=key_factors,
                evidence_citations=evidence_citations,
                source=ExplanationSource.CONSTRAINED_LLM,
                model_identifier=model_identifier,
                guardrails_passed=True,
                guardrail_validation_details=guardrail_result.checks_evaluated,
                execution_metadata=metadata,
            )
            self.db.add(record)
        else:
            record.summary_narrative = summary_narrative
            record.primary_driver = primary_driver
            record.key_factors = key_factors
            record.evidence_citations = evidence_citations
            record.model_identifier = model_identifier
            record.guardrails_passed = True
            record.guardrail_validation_details = guardrail_result.checks_evaluated
            record.execution_metadata = metadata
            record.updated_at = datetime.now(timezone.utc)

        await self.db.flush()
        return record