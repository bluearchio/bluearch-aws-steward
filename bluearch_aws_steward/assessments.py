from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import BoundedSemaphore, Event, Lock, Thread
from typing import Any, Callable, Dict, Optional
from uuid import uuid4

JSON = Dict[str, Any]
AssessmentRunner = Callable[[JSON], JSON]
TERMINAL_STATUSES = {"completed", "failed", "cancelled"}
DEFAULT_MAX_FINDINGS = 50_000


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class AssessmentJob:
    assessment_id: str
    request: JSON
    status: str = "queued"
    created_at: datetime = field(default_factory=_utc_now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    result: Optional[JSON] = None
    partial_result: Optional[JSON] = None
    error: Optional[str] = None
    progress: JSON = field(
        default_factory=lambda: {
            "phase": "queued",
            "message": "Assessment is waiting for an available scan worker.",
        }
    )
    done: Event = field(default_factory=Event, repr=False)
    cancel_requested: Event = field(default_factory=Event, repr=False)


class AssessmentStore:
    """Process-local assessment jobs with bounded concurrency and expiration."""

    def __init__(
        self,
        runner: AssessmentRunner,
        *,
        ttl_seconds: int = 900,
        max_jobs: int = 100,
        max_concurrent: int = 2,
        max_findings: int = DEFAULT_MAX_FINDINGS,
    ) -> None:
        self._runner = runner
        self._ttl = timedelta(seconds=max(1, ttl_seconds))
        self._max_jobs = max(1, max_jobs)
        self._max_findings = max(1, max_findings)
        self._jobs: Dict[str, AssessmentJob] = {}
        self._lock = Lock()
        self._slots = BoundedSemaphore(max(1, max_concurrent))

    def submit(self, request: JSON) -> JSON:
        with self._lock:
            self._cleanup_locked()
            self._make_room_locked()
            job = AssessmentJob(
                assessment_id=f"assessment_{uuid4().hex}",
                request=deepcopy(request),
            )
            self._jobs[job.assessment_id] = job
            submitted = self._snapshot(job)

        Thread(
            target=self._run,
            args=(job.assessment_id,),
            name=f"bluearch-{job.assessment_id[-8:]}",
            daemon=True,
        ).start()
        return submitted

    def get(
        self,
        assessment_id: str,
        *,
        include_result: bool = False,
        include_partial: bool = False,
    ) -> JSON:
        with self._lock:
            self._cleanup_locked()
            job = self._jobs.get(assessment_id)
            if job is None:
                raise KeyError(assessment_id)
            return self._snapshot(
                job,
                include_result=include_result,
                include_partial=include_partial,
            )

    def cancel(self, assessment_id: str) -> JSON:
        with self._lock:
            self._cleanup_locked()
            job = self._jobs.get(assessment_id)
            if job is None:
                raise KeyError(assessment_id)
            if job.status in TERMINAL_STATUSES:
                return self._snapshot(job, include_partial=True)
            job.cancel_requested.set()
            if job.status == "queued":
                completed_at = _utc_now()
                job.status = "cancelled"
                job.completed_at = completed_at
                job.expires_at = completed_at + self._ttl
                job.progress = {
                    "phase": "cancelled",
                    "message": "Assessment was cancelled before AWS evaluation started.",
                }
                job.done.set()
            else:
                job.progress = {
                    **job.progress,
                    "phase": "cancelling",
                    "message": "Cancellation requested; in-flight read-only AWS calls may finish.",
                }
            return self._snapshot(job, include_partial=True)

    def get_request(self, assessment_id: str) -> JSON:
        with self._lock:
            self._cleanup_locked()
            job = self._jobs.get(assessment_id)
            if job is None:
                raise KeyError(assessment_id)
            return deepcopy(job.request)

    def wait(self, assessment_id: str, timeout: Optional[float] = None) -> JSON:
        with self._lock:
            job = self._jobs.get(assessment_id)
            if job is None:
                raise KeyError(assessment_id)
            done = job.done
        done.wait(timeout)
        return self.get(assessment_id, include_result=True)

    def _run(self, assessment_id: str) -> None:
        with self._slots:
            with self._lock:
                job = self._jobs.get(assessment_id)
                if job is None or job.status in TERMINAL_STATUSES:
                    return
                job.status = "running"
                job.started_at = _utc_now()
                job.progress = {
                    "phase": "starting",
                    "message": "Steward is preparing live AWS rule evaluation.",
                }
                request = deepcopy(job.request)
                request["_progress_callback"] = lambda update: self._update_progress(
                    assessment_id,
                    update,
                )
                request["_partial_callback"] = lambda result: self._update_partial(
                    assessment_id,
                    result,
                )
                request["_cancel_event"] = job.cancel_requested

            try:
                result = self._runner(request)
            except Exception as exc:  # noqa: BLE001 - background boundary must preserve job state
                with self._lock:
                    job = self._jobs.get(assessment_id)
                    cancelled = bool(job and job.cancel_requested.is_set())
                    partial = deepcopy(job.partial_result) if job and job.partial_result else None
                if cancelled:
                    self._finish(assessment_id, status="cancelled", result=partial)
                    return
                detail = getattr(exc, "detail", None)
                error = f"{exc}\n{detail}" if detail else str(exc)
                self._finish(assessment_id, status="failed", error=error)
                return

            with self._lock:
                job = self._jobs.get(assessment_id)
                cancelled = bool(job and job.cancel_requested.is_set())
            self._finish(
                assessment_id,
                status="cancelled" if cancelled else "completed",
                result=result,
            )

    def _finish(
        self,
        assessment_id: str,
        *,
        status: str,
        result: Optional[JSON] = None,
        error: Optional[str] = None,
    ) -> None:
        with self._lock:
            job = self._jobs.get(assessment_id)
            if job is None:
                return
            completed_at = _utc_now()
            job.status = status
            job.completed_at = completed_at
            job.expires_at = completed_at + self._ttl
            job.result = self._guard_result(result) if result is not None else None
            job.error = error
            job.progress = {
                **job.progress,
                "phase": status,
                "message": (
                    "Assessment completed. Results are ready."
                    if status == "completed"
                    else (
                        "Assessment cancelled. Any completed read-only results were preserved."
                        if status == "cancelled"
                        else "Assessment failed. Review the reported error before retrying."
                    )
                ),
            }
            job.done.set()

    def _update_progress(self, assessment_id: str, update: JSON) -> None:
        with self._lock:
            job = self._jobs.get(assessment_id)
            if job is None or job.status in TERMINAL_STATUSES:
                return
            job.progress = {**job.progress, **deepcopy(update)}

    def _update_partial(self, assessment_id: str, result: JSON) -> None:
        with self._lock:
            job = self._jobs.get(assessment_id)
            if job is None or job.status in TERMINAL_STATUSES:
                return
            job.partial_result = self._guard_result(result)

    def _guard_result(self, result: JSON) -> JSON:
        guarded = deepcopy(result)
        primary_key = next(
            (
                key
                for key in (
                    "complete_opportunities",
                    "complete_findings",
                    "opportunities",
                    "findings",
                )
                if isinstance(guarded.get(key), list)
            ),
            None,
        )
        if primary_key is None:
            return guarded
        observed = len(guarded[primary_key])
        if observed <= self._max_findings:
            return guarded

        for key in ("complete_opportunities", "complete_findings", "opportunities", "findings"):
            if isinstance(guarded.get(key), list):
                guarded[key] = guarded[key][: self._max_findings]
        summary = dict(guarded.get("summary") or {})
        summary.update(
            {
                "incomplete": True,
                "incomplete_reason": "assessment_memory_guard_reached",
                "findings_observed_before_guard": observed,
                "findings_retained": self._max_findings,
                "finding_memory_guard": self._max_findings,
            }
        )
        guarded["summary"] = summary
        return guarded

    def _snapshot(
        self,
        job: AssessmentJob,
        *,
        include_result: bool = False,
        include_partial: bool = False,
    ) -> JSON:
        payload: JSON = {
            "assessment_id": job.assessment_id,
            "status": job.status,
            "created_at": _iso(job.created_at),
            "started_at": _iso(job.started_at),
            "completed_at": _iso(job.completed_at),
            "expires_at": _iso(job.expires_at),
            "progress": deepcopy(job.progress),
            "request": self._public_request(job.request),
            "ephemeral": True,
            "point_in_time": True,
            "cancel_requested": job.cancel_requested.is_set(),
        }
        if job.error:
            payload["error"] = job.error
        if job.result is not None:
            payload["summary"] = deepcopy(job.result.get("summary") or {})
            payload["observed_at"] = job.result.get("observed_at") or _iso(job.completed_at)
            if include_result:
                payload["result"] = deepcopy(job.result)
        if job.partial_result is not None:
            payload["partial_summary"] = deepcopy(job.partial_result.get("summary") or {})
            if include_partial:
                payload["partial_result"] = deepcopy(job.partial_result)
        return payload

    def _public_request(self, request: JSON) -> JSON:
        allowed = {
            "prompt",
            "objective",
            "objectives",
            "service",
            "services",
            "assessment_mode",
            "result_preferences",
            "provider",
            "profile",
            "region",
            "bucket_prefix",
            "rule_filter",
            "max_returned_resources",
            "max_returned_findings",
            "ebs_min_unattached_days",
            "cloudwatch_retention_days",
            "cloudwatch_min_stored_bytes",
            "exclude_tags",
        }
        payload = {key: deepcopy(value) for key, value in request.items() if key in allowed}
        if "scan_result" in request:
            payload["uses_supplied_scan_result"] = True
        return payload

    def _cleanup_locked(self) -> None:
        now = _utc_now()
        expired = [
            assessment_id
            for assessment_id, job in self._jobs.items()
            if job.status in TERMINAL_STATUSES
            and job.expires_at is not None
            and job.expires_at <= now
        ]
        for assessment_id in expired:
            del self._jobs[assessment_id]

    def _make_room_locked(self) -> None:
        if len(self._jobs) < self._max_jobs:
            return
        terminal = sorted(
            (job for job in self._jobs.values() if job.status in TERMINAL_STATUSES),
            key=lambda job: job.completed_at or job.created_at,
        )
        if terminal:
            del self._jobs[terminal[0].assessment_id]
            return
        raise RuntimeError(
            "Too many Steward assessments are currently running. Retry after one completes."
        )
