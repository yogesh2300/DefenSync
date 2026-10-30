"""Account / data-scope helper tests (no ML retraining, no dataset re-import)."""

from backend.database.models import DATA_SCOPE_GLOBAL, DATA_SCOPE_PRIVATE
from backend.database.scope import infer_data_scope, YOGESH_ACCOUNT_NAME


def test_live_linux_is_private():
    assert infer_data_scope("LIVE_LINUX") == DATA_SCOPE_PRIVATE


def test_public_dataset_is_global():
    assert infer_data_scope("PUBLIC_DATASET") == DATA_SCOPE_GLOBAL
    assert infer_data_scope("SYNTHETIC") == DATA_SCOPE_GLOBAL
    assert infer_data_scope("SYNTHETIC_CLOUD_DEMO") == DATA_SCOPE_GLOBAL


def test_global_explicit_overrides_origin():
    assert infer_data_scope("LIVE_LINUX", "GLOBAL") == DATA_SCOPE_GLOBAL


def test_yogesh_account_name():
    assert YOGESH_ACCOUNT_NAME == "Yogesh"
