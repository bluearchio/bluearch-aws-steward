from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from bluearch_aws_steward.providers.base import AwsProvider


@dataclass(frozen=True)
class MetricSignalQuery:
    key: str
    namespace: str
    metric_name: str
    dimensions: Tuple[Tuple[str, str], ...]
    statistic: str
    lookback_days: int
    period_seconds: int = 86400


@dataclass(frozen=True)
class MetricSeries:
    key: str
    values: Tuple[float, ...]
    timestamps: Tuple[str, ...]
    complete: bool


class CloudWatchSignalAdapter:
    """Assessment-local CloudWatch metric reader with bounded batching."""

    def __init__(self, provider: AwsProvider, *, now: datetime | None = None) -> None:
        self._provider = provider
        self._now = now or datetime.now(timezone.utc)
        self._cache: Dict[MetricSignalQuery, MetricSeries] = {}

    def read(self, queries: Iterable[MetricSignalQuery]) -> Dict[str, MetricSeries]:
        requested = list(dict.fromkeys(queries))
        missing = [query for query in requested if query not in self._cache]
        for offset in range(0, len(missing), 500):
            self._read_batch(missing[offset : offset + 500])
        return {query.key: self._cache[query] for query in requested}

    def _read_batch(self, queries: Sequence[MetricSignalQuery]) -> None:
        if not queries:
            return
        start_time = min(
            self._now - timedelta(days=max(1, query.lookback_days)) for query in queries
        )
        id_to_query: Dict[str, MetricSignalQuery] = {}
        metric_queries: List[Dict[str, Any]] = []
        for index, query in enumerate(queries):
            query_id = _metric_query_id(index, query.key)
            id_to_query[query_id] = query
            metric_queries.append(
                {
                    "Id": query_id,
                    "Label": query.key,
                    "ReturnData": True,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": query.namespace,
                            "MetricName": query.metric_name,
                            "Dimensions": [
                                {"Name": name, "Value": value} for name, value in query.dimensions
                            ],
                        },
                        "Period": query.period_seconds,
                        "Stat": query.statistic,
                    },
                }
            )

        response = self._provider.read(
            "cloudwatch.get_metric_data",
            MetricDataQueries=metric_queries,
            StartTime=start_time,
            EndTime=self._now,
            ScanBy="TimestampAscending",
        )
        returned = {
            str(item.get("Id") or ""): item
            for item in response.get("MetricDataResults") or []
            if isinstance(item, Mapping)
        }
        for query_id, query in id_to_query.items():
            item = returned.get(query_id) or {}
            values = tuple(float(value) for value in item.get("Values") or [])
            timestamps = tuple(_timestamp(value) for value in item.get("Timestamps") or [])
            self._cache[query] = MetricSeries(
                key=query.key,
                values=values,
                timestamps=timestamps,
                complete=bool(values) and str(item.get("StatusCode") or "Complete") == "Complete",
            )


def _metric_query_id(index: int, key: str) -> str:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]
    return f"m{index}_{digest}"


def _timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)
