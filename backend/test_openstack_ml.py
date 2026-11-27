"""OpenStack cloud-API Isolation Forest demonstration: parser, window features, leakage, model."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pytest

from backend.core.config import PROJECT_ROOT, get_settings
from backend.ml import openstack_isolation_forest as osif
from backend.ml.openstack_features import (
    EXCLUDED_FIELDS,
    FEATURE_NAMES,
    FEATURE_VERSION,
    ParseStats,
    build_windows,
    iter_file,
    parse_line,
    window_start,
)
from backend.services.ml_demo_service import (
    OPENSTACK_FILES,
    STATUS_DATASET_MISSING,
    STATUS_NOT_TRAINED,
    STATUS_STALE,
    STATUS_TRAINED,
    OpenStackDemoService,
)

BASE = datetime(2017, 5, 16, 0, 0, 0)
USER = "113d3a99c3da401fbd62cc2caa5b96d2"
PROJECT = "54fadb412c4e40cdbaed9335e4c35a9e"
INSTANCE = "544fd51c-4edc-4780-baae-ba1d80a0acfc"


def _stamp(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 1000:03d}"


def api_line(
    ts: datetime,
    *,
    method: str = "GET",
    status: int = 200,
    length: int = 1893,
    latency: float = 0.26,
    user: str = USER,
    project: str = PROJECT,
    req: str = "req-38101a0b-2096-447d-96ea-a692162415ae",
    ip: str = "10.11.10.1",
    source: str = "nova-api.log.1.2017-05-16_13:53:08",
    level: str = "INFO",
) -> str:
    return (
        f"{source} {_stamp(ts)} 25746 {level} nova.osapi_compute.wsgi.server [{req} {user} {project} - - -] "
        f"{ip} \"{method} /v2/{project}/servers/detail HTTP/1.1\" status: {status} len: {length} time: {latency:.7f}"
    )


def compute_line(
    ts: datetime,
    message: str,
    *,
    instance: str = INSTANCE,
    component: str = "nova.compute.manager",
    source: str = "nova-compute.log.1.2017-05-16_13:55:31",
    req: str = "req-3ea4052c-895d-4b64-9e2d-04d64c4d94ab",
) -> str:
    return f"{source} {_stamp(ts)} 2931 INFO {component} [{req} - - - - -] [instance: {instance}] {message}"


def baseline_lines(windows: int, *, start: datetime = BASE, **overrides) -> list[str]:
    """Steady polling: one GET every 10 s plus one VM lifecycle sequence per window."""
    lines = []
    for w in range(windows):
        origin = start + timedelta(minutes=5 * w)
        for i in range(30):
            jitter = 0.24 + 0.01 * ((w + i) % 5)
            lines.append(api_line(origin + timedelta(seconds=10 * i), latency=jitter, **overrides))
        instance = f"{w:08x}-0000-4000-8000-000000000000"
        lines.append(compute_line(origin + timedelta(seconds=20), "VM Started (Lifecycle Event)", instance=instance))
        lines.append(compute_line(origin + timedelta(seconds=21), "VM Paused (Lifecycle Event)", instance=instance))
        lines.append(compute_line(origin + timedelta(seconds=30), "VM Resumed (Lifecycle Event)", instance=instance))
        lines.append(compute_line(
            origin + timedelta(seconds=31), "Took 19.8%d seconds to spawn the instance on the hypervisor." % (w % 10),
            instance=instance,
        ))
    return lines


def records(lines: list[str]):
    parsed = [parse_line(line) for line in lines]
    assert all(item is not None for item in parsed)
    return parsed


# ---------------------------------------------------------------- parser


def test_parse_api_line_extracts_http_and_identity_fields():
    rec = parse_line(api_line(BASE, method="POST", status=202, length=733, latency=1.5))
    assert rec.timestamp == BASE
    assert rec.level == "INFO" and rec.component == "nova.osapi_compute.wsgi.server"
    assert rec.request_id.startswith("req-")
    assert (rec.user_id, rec.project_id) == (USER, PROJECT)
    assert (rec.method, rec.status, rec.response_length, rec.latency) == ("POST", 202, 733, 1.5)
    assert rec.client_ip == "10.11.10.1"
    assert rec.source_file.startswith("nova-api.log")
    assert rec.instance_id is None


def test_parse_compute_line_with_instance_and_empty_identity():
    rec = parse_line(compute_line(BASE, "VM Paused (Lifecycle Event)"))
    assert rec.instance_id == INSTANCE
    assert rec.user_id is None and rec.project_id is None
    assert rec.method is None and rec.status is None
    assert "VM Paused" in rec.message


def test_parse_line_without_context_or_source_prefix():
    rec = parse_line(f"{_stamp(BASE)} 2931 INFO nova.virt.libvirt.driver [-] [instance: {INSTANCE}] Instance destroyed successfully.")
    assert rec is not None and rec.source_file is None
    assert rec.request_id is None and rec.instance_id == INSTANCE


@pytest.mark.parametrize("line", ["", "garbage line", "2017-05-16 not-a-time 1 INFO x y", "nova.log 2017-13-45 00:00:00.000 1 INFO c m"])
def test_parse_line_rejects_malformed_lines(line):
    assert parse_line(line) is None


def test_iter_file_counts_unparsed_lines(tmp_path):
    path = tmp_path / "sample.log"
    path.write_text("\n".join([api_line(BASE), "not an openstack line", "", api_line(BASE + timedelta(seconds=1))]), encoding="utf-8")
    stats = ParseStats()
    parsed = list(iter_file(path, stats))
    assert len(parsed) == 2
    assert (stats.lines, stats.parsed, stats.unparsed) == (3, 2, 1)
    assert parsed[0].source_file == "sample.log" and parsed[0].line_number == 1


# ---------------------------------------------------------------- features


def test_window_start_floors_to_five_minutes():
    assert window_start(datetime(2017, 5, 16, 10, 7, 59, 999000)) == datetime(2017, 5, 16, 10, 5)
    assert window_start(datetime(2017, 5, 16, 10, 5, 0)) == datetime(2017, 5, 16, 10, 5)


def test_window_feature_values():
    lines = [
        api_line(BASE, latency=0.2, length=100),
        api_line(BASE + timedelta(seconds=30), method="POST", status=202, latency=0.4, length=300, user="u2"),
        api_line(BASE + timedelta(seconds=60), method="DELETE", status=204, latency=0.6, length=0),
        api_line(BASE + timedelta(seconds=90), status=404, latency=1.0, length=50, ip="10.11.10.7"),
        api_line(BASE + timedelta(seconds=120), status=503, latency=3.0, length=10),
        compute_line(BASE + timedelta(seconds=130), "VM Started (Lifecycle Event)"),
        compute_line(BASE + timedelta(seconds=140), "VM Resumed (Lifecycle Event)"),
        compute_line(BASE + timedelta(seconds=150), "Took 20.50 seconds to spawn the instance on the hypervisor."),
        compute_line(BASE + timedelta(seconds=160), "Took 21.00 seconds to build instance."),
        compute_line(BASE + timedelta(seconds=170), "Took 0.90 seconds to destroy the instance on the hypervisor.", instance="ae651dff-c7ad-43d6-ac96-bbcd820ccca8"),
        compute_line(BASE + timedelta(seconds=200), "Attempting claim", component="nova.compute.claims"),
    ]
    matrix = build_windows(records(lines))
    assert len(matrix) == 1 and matrix.values.shape == (1, len(FEATURE_NAMES))
    f = dict(zip(FEATURE_NAMES, matrix.values[0]))
    assert f["events_total"] == 11 and f["api_requests"] == 5
    assert f["requests_per_minute"] == pytest.approx(1.0)
    assert (f["get_requests"], f["post_requests"], f["delete_requests"], f["other_method_requests"]) == (3, 1, 1, 0)
    assert f["post_ratio"] == pytest.approx(0.2) and f["delete_ratio"] == pytest.approx(0.2)
    assert f["status_2xx_ratio"] == pytest.approx(0.6)
    assert f["status_4xx_ratio"] == pytest.approx(0.2) and f["status_5xx_ratio"] == pytest.approx(0.2)
    assert f["latency_mean"] == pytest.approx(1.04) and f["latency_max"] == pytest.approx(3.0)
    assert f["latency_p95"] == pytest.approx(np.percentile([0.2, 0.4, 0.6, 1.0, 3.0], 95))
    assert f["response_length_mean"] == pytest.approx(92.0) and f["response_length_max"] == 300
    assert f["compute_api_requests"] == 5 and f["compute_manager_events"] == 5 and f["claims_events"] == 1
    assert (f["vm_started"], f["vm_resumed"], f["vm_paused"], f["vm_stopped"]) == (1, 1, 0, 0)
    assert f["spawn_seconds_mean"] == pytest.approx(20.5) and f["build_seconds_max"] == pytest.approx(21.0)
    assert f["destroy_seconds_max"] == pytest.approx(0.9)
    assert (f["distinct_users"], f["distinct_projects"], f["distinct_active_instances"], f["distinct_client_ips"]) == (2, 1, 2, 2)


def test_partial_windows_are_excluded():
    lines = baseline_lines(3) + [api_line(BASE + timedelta(minutes=15, seconds=5))]
    matrix = build_windows(records(lines))
    assert len(matrix) == 3 and matrix.excluded_partial == 1
    assert matrix.window_starts == [BASE + timedelta(minutes=5 * i) for i in range(3)]


def test_feature_matrix_shape_order_and_instances_kept_out_of_values():
    matrix = build_windows(records(baseline_lines(6)))
    assert matrix.feature_names == FEATURE_NAMES and FEATURE_VERSION == "openstack-v1"
    assert matrix.values.shape == (6, len(FEATURE_NAMES)) and np.isfinite(matrix.values).all()
    assert all(len(instances) == 1 for instances in matrix.window_instances)
    assert matrix.window_starts == sorted(matrix.window_starts)


# ---------------------------------------------------------------- leakage


FORBIDDEN_TOKENS = ("label", "file", "source", "date", "hour", "day", "request_id", "instance_id", "line", "level", "severity", "risk", "alert", "detection", "collection")


def test_feature_names_exclude_leakage_fields():
    for name in FEATURE_NAMES:
        assert not any(token in name for token in FORBIDDEN_TOKENS), name
    for field in ("anomaly_label", "source_file", "date", "request_id", "instance_id", "log_level"):
        assert field in EXCLUDED_FIELDS


def test_features_invariant_to_identifiers_file_and_level():
    original = records(baseline_lines(4))
    changed = [
        dataclasses.replace(
            rec,
            source_file="openstack_abnormal.log",
            line_number=rec.line_number + 999,
            request_id="req-ffffffff-ffff-4fff-8fff-ffffffffffff",
            instance_id=(rec.instance_id[::-1] if rec.instance_id else None),
            user_id=("other-user" if rec.user_id else None),
            project_id=("other-project" if rec.project_id else None),
            client_ip=("192.0.2.9" if rec.client_ip else None),
            level="WARNING",
        )
        for rec in original
    ]
    assert np.array_equal(build_windows(original).values, build_windows(changed).values)


def test_features_invariant_to_calendar_date_shift():
    original = records(baseline_lines(4))
    shifted = [dataclasses.replace(rec, timestamp=rec.timestamp + timedelta(days=3, hours=7)) for rec in original]
    a, b = build_windows(original), build_windows(shifted)
    assert np.array_equal(a.values, b.values)
    assert a.window_starts != b.window_starts


def test_training_does_not_read_labels_and_evaluation_is_post_hoc():
    matrix = build_windows(records(baseline_lines(60)))
    first = osif.train_bundle(matrix, trained_at=BASE)
    scores = osif.score_windows(first, matrix)
    with_labels = osif.evaluate(scores, matrix, [f"{3:08x}-0000-4000-8000-000000000000"])
    second = osif.train_bundle(matrix, trained_at=BASE)
    assert [r["anomaly_score"] for r in osif.score_windows(second, matrix)] == [r["anomaly_score"] for r in scores]
    assert with_labels["windows_with_labelled_instances"] == 1
    assert "Post-hoc" in with_labels["purpose"]
    assert "anomaly_label" in first["training_metadata"]["excluded_fields"]


# ---------------------------------------------------------------- Isolation Forest


def test_train_bundle_requires_minimum_windows():
    with pytest.raises(ValueError, match="at least"):
        osif.train_bundle(build_windows(records(baseline_lines(osif.MIN_TRAINING_WINDOWS - 1))))


def test_train_bundle_metadata_and_compatibility(tmp_path):
    matrix = build_windows(records(baseline_lines(60)))
    bundle = osif.train_bundle(matrix, trained_at=BASE)
    meta = bundle["training_metadata"]
    assert osif.is_compatible(bundle)
    assert bundle["model_version"] == "openstack-if-v1" and bundle["data_source"] == "OPENSTACK_PUBLIC_DATASET"
    assert bundle["model"].random_state == osif.RANDOM_STATE
    assert meta["training_windows"] == 60 and meta["threshold_percentile"] == osif.THRESHOLD_PERCENTILE
    assert meta["training_above_threshold"] <= int(0.05 * 60) + 1
    path = tmp_path / "m.joblib"
    osif.save_bundle(bundle, path)
    loaded = osif.load_bundle(path)
    assert loaded is not None and loaded["threshold"] == bundle["threshold"]
    assert not osif.is_compatible({**bundle, "feature_version": "linux-v1"})
    assert not osif.is_compatible({**bundle, "kind": "linux_isolation_forest"})


def test_isolation_forest_is_deterministic():
    matrix = build_windows(records(baseline_lines(60)))
    a = osif.score_windows(osif.train_bundle(matrix, trained_at=BASE), matrix)
    b = osif.score_windows(osif.train_bundle(matrix, trained_at=BASE), matrix)
    assert a == b


def test_unusual_window_is_flagged_with_evidence():
    lines = baseline_lines(60)
    burst = BASE + timedelta(minutes=5 * 60)
    for i in range(150):
        lines.append(api_line(burst + timedelta(seconds=2 * i), method="DELETE", status=500, latency=9.0, length=0))
    matrix = build_windows(records(lines))
    results = osif.score_windows(osif.train_bundle(matrix, trained_at=BASE), matrix)
    last = results[-1]
    assert last["window_start"] == burst.isoformat()
    assert last["result"] == osif.RESULT_ANOMALOUS
    assert last["anomaly_score"] == max(r["anomaly_score"] for r in results)
    assert {"anomaly_score", "threshold", "result", "features", "evidence", "model_version", "data_source"} <= set(last)
    assert set(last["features"]) == set(FEATURE_NAMES)
    assert last["evidence"] and all(item["feature"] in FEATURE_NAMES for item in last["evidence"])
    assert all(r["evidence"] == [] for r in results if r["result"] == osif.RESULT_NORMAL)


# ---------------------------------------------------------------- service


def _settings(tmp_path: Path):
    settings = get_settings().model_copy()
    settings.DATASET_ROOT = str(tmp_path / "datasets")
    settings.OPENSTACK_DATASET_PATH = "OpenStack"
    settings.MODEL_DIR = str(tmp_path / "models")
    return settings


def _write_dataset(tmp_path: Path) -> Path:
    raw = tmp_path / "datasets" / "OpenStack" / "raw"
    raw.mkdir(parents=True)
    starts = [BASE, BASE + timedelta(days=1), BASE - timedelta(days=2)]
    for name, start in zip(OPENSTACK_FILES, starts):
        (raw / name).write_text("\n".join(baseline_lines(25, start=start)), encoding="utf-8")
    (raw / "anomaly_labels.txt").write_text(f"header line\n\n{2:08x}-0000-4000-8000-000000000000\n", encoding="utf-8")
    return raw


def test_service_train_report_and_staleness(tmp_path):
    settings = _settings(tmp_path)
    service = OpenStackDemoService(settings)
    assert service.report()["status"] == STATUS_DATASET_MISSING
    raw = _write_dataset(tmp_path)
    assert service.report()["status"] == STATUS_NOT_TRAINED
    trained = service.train()
    assert trained["status"] == STATUS_TRAINED
    assert trained["is_azure"] is False and trained["is_live"] is False
    assert "Not Azure" in trained["disclaimer"] and "not account compromise" in trained["disclaimer"]
    assert trained["summary"]["windows_scored"] == 75
    assert trained["evaluation"]["labelled_instances"] == 1
    assert len(trained["window_scores"]) == 75
    assert [f["name"] for f in trained["dataset"]["files"]] == list(OPENSTACK_FILES)
    assert service.model_file.is_relative_to(Path(settings.MODEL_DIR) / "demo" / "openstack")
    assert service.report()["status"] == STATUS_TRAINED
    (raw / OPENSTACK_FILES[0]).write_text("\n".join(baseline_lines(26)), encoding="utf-8")
    assert service.report()["status"] == STATUS_STALE


def test_ml_demo_routes_are_registered_and_authenticated():
    from backend.main import app

    paths = app.openapi()["paths"]
    expected = [
        ("/api/v1/ml-demo/openstack", "get"),
        ("/api/v1/ml-demo/openstack/train", "post"),
        ("/api/v1/ml-demo/behavioral", "get"),
        ("/api/v1/ml-demo/behavioral/train", "post"),
        ("/api/v1/ml-demo/behavioral/predict", "post"),
    ]
    for path, method in expected:
        operation = paths.get(path, {}).get(method)
        assert operation is not None, (path, method)
        assert operation.get("security"), (path, method)


REAL_RAW = PROJECT_ROOT / "datasets" / "OpenStack" / "raw"


@pytest.mark.skipif(not all((REAL_RAW / name).is_file() for name in OPENSTACK_FILES), reason="OpenStack raw dataset not present")
def test_real_openstack_dataset_parses_completely(tmp_path):
    settings = get_settings().model_copy()
    settings.MODEL_DIR = str(tmp_path / "models")
    report = OpenStackDemoService(settings).train()
    assert all(item["unparsed"] == 0 for item in report["dataset"]["files"])
    assert report["dataset"]["records_parsed"] == sum(item["parsed"] for item in report["dataset"]["files"])
    assert report["summary"]["windows_scored"] > osif.MIN_TRAINING_WINDOWS
    assert report["evaluation"]["labelled_instances"] == 4
