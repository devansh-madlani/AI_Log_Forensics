import sys
import os
from datetime import timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.features.feature_extraction import extract_features, FEATURE_COLUMNS
from app.demo.synthetic_data import generate
from app.normalizer.normalize import normalize_batch
from app.schemas import DataOrigin, NormalizedEvent

IST = timezone(timedelta(hours=5, minutes=30))
PACIFIC = timezone(timedelta(hours=-7))


def _demo_normalized_events():
    raw = generate(num_normal_events=40)
    return normalize_batch(raw)


def test_extract_features_returns_all_columns():
    events = _demo_normalized_events()
    df = extract_features(events)
    assert list(df.columns) == FEATURE_COLUMNS
    assert len(df) == len(events)


def test_extract_features_empty_input():
    df = extract_features([])
    assert len(df) == 0
    assert list(df.columns) == FEATURE_COLUMNS


def test_features_attached_back_to_events():
    events = _demo_normalized_events()
    extract_features(events)
    assert all(e.features for e in events)
    assert all("hour_of_day" in e.features for e in events)


def test_failed_logon_flag_set_correctly():
    events = _demo_normalized_events()
    extract_features(events)
    failed_logons = [e for e in events if e.event_id == 4625]
    assert len(failed_logons) > 0
    assert all(e.features["is_failed_logon"] == 1 for e in failed_logons)
    non_failed = [e for e in events if e.event_id != 4625]
    assert all(e.features["is_failed_logon"] == 0 for e in non_failed)


def test_powershell_suspicious_flag():
    events = _demo_normalized_events()
    extract_features(events)
    ps_events = [e for e in events if e.process_name == "powershell.exe"]
    assert len(ps_events) > 0
    assert all(e.features["is_powershell_suspicious"] == 1 for e in ps_events)


def test_rarity_is_bounded_between_0_and_1():
    events = _demo_normalized_events()
    df = extract_features(events)
    for col in ["event_type_rarity", "process_rarity", "source_ip_rarity", "user_activity_rarity"]:
        assert df[col].min() >= 0.0
        assert df[col].max() <= 1.0


def _event_at(timestamp: str, origin: str = DataOrigin.OBSERVED.value) -> NormalizedEvent:
    return NormalizedEvent(
        data_origin=origin, operating_system="Windows", timestamp=timestamp,
        event_id=4624, log_source="Security", event_type="Successful Logon",
        severity="Informational", message="m",
    )


def test_observed_utc_timestamp_is_judged_in_host_local_time():
    # 05:16 UTC is 10:46 IST - normal working hours on an IST host.
    e = _event_at("2026-10-01T05:16:00+00:00")
    extract_features([e], local_tz=IST)
    assert e.features["hour_of_day"] == 10
    assert e.features["is_off_hours"] == 0


def test_observed_late_night_local_time_is_off_hours():
    # 17:41 UTC is 23:11 IST - genuinely off-hours on the host.
    e = _event_at("2026-10-01T17:41:00+00:00")
    extract_features([e], local_tz=IST)
    assert e.features["hour_of_day"] == 23
    assert e.features["is_off_hours"] == 1


def test_observed_naive_timestamp_is_used_as_wall_clock():
    e = _event_at("2026-10-01T10:46:00")
    extract_features([e], local_tz=PACIFIC)
    assert e.features["hour_of_day"] == 10
    assert e.features["is_off_hours"] == 0


def test_unparseable_timestamp_falls_back_to_neutral_hour():
    e = _event_at("not-a-timestamp")
    extract_features([e], local_tz=IST)
    assert e.features["hour_of_day"] == 12
    assert e.features["is_off_hours"] == 0


def test_synthetic_demo_timestamp_keeps_its_authored_clock():
    # Demo data is authored on a UTC demo day; the host timezone must not move it.
    e = _event_at("2026-10-01T05:16:00+00:00", origin=DataOrigin.SYNTHETIC_DEMO.value)
    extract_features([e], local_tz=IST)
    assert e.features["hour_of_day"] == 5
    assert e.features["is_off_hours"] == 1


def test_demo_off_hours_flags_do_not_depend_on_host_timezone():
    flags_by_tz = []
    for tz in (timezone.utc, IST, PACIFIC):
        events = _demo_normalized_events()
        extract_features(events, local_tz=tz)
        flags_by_tz.append([(e.features["hour_of_day"], e.features["is_off_hours"]) for e in events])
    assert flags_by_tz[0] == flags_by_tz[1] == flags_by_tz[2]
    # The demo day runs from 08:00 UTC; its normal background activity is in working hours.
    assert all(hour >= 7 for hour, _ in flags_by_tz[0])
