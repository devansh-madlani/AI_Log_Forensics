import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Base, engine, SessionLocal
from app import pipeline, models
from app.demo.synthetic_data import generate as generate_demo


def setup_function(_):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_full_pipeline_demo_data_end_to_end():
    db = SessionLocal()
    try:
        raw = generate_demo(num_normal_events=80)
        ingest_result = pipeline.ingest_raw_events(db, raw, batch_id="test-batch-1")
        assert ingest_result["events_ingested"] == len(raw)

        stored = db.query(models.Event).filter(models.Event.batch_id == "test-batch-1").all()
        assert len(stored) == len(raw)
        assert all(e.analyzed is False for e in stored)
        assert all(e.data_origin == "SYNTHETIC_DEMO" for e in stored)
        # raw evidence preserved
        assert all(e.raw_data for e in stored)

        analysis_result = pipeline.run_analysis(db, batch_id="test-batch-1")
        assert analysis_result["analyzed_events"] == len(raw)

        db.expire_all()
        analyzed = db.query(models.Event).filter(models.Event.batch_id == "test-batch-1").all()
        assert all(e.analyzed is True for e in analyzed)
        assert all(e.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL") for e in analyzed)
        assert all(0.0 <= e.anomaly_score <= 1.0 for e in analyzed)
        assert all(0.0 <= e.risk_score <= 100.0 for e in analyzed)
        assert all(e.analysis_reasons for e in analyzed)

        # The injected attack storyline should produce at least one
        # HIGH or CRITICAL event.
        high_risk = [e for e in analyzed if e.risk_level in ("HIGH", "CRITICAL")]
        assert len(high_risk) > 0
    finally:
        db.close()


def test_analysis_only_touches_unanalyzed_events_by_default():
    db = SessionLocal()
    try:
        raw = generate_demo(num_normal_events=30)
        pipeline.ingest_raw_events(db, raw, batch_id="batch-a")
        pipeline.run_analysis(db, batch_id="batch-a")

        # ingest a second batch, don't analyze it explicitly
        raw2 = generate_demo(num_normal_events=20, seed=99)
        pipeline.ingest_raw_events(db, raw2, batch_id="batch-b")

        # default run_analysis() with no batch_id should only pick up
        # the un-analyzed batch-b events
        result = pipeline.run_analysis(db)
        assert result["analyzed_events"] == len(raw2)
    finally:
        db.close()


def test_raw_data_never_mutated_by_analysis():
    db = SessionLocal()
    try:
        raw = generate_demo(num_normal_events=20)
        pipeline.ingest_raw_events(db, raw, batch_id="batch-evidence")

        before = {
            e.event_uid: e.raw_data
            for e in db.query(models.Event).filter(models.Event.batch_id == "batch-evidence").all()
        }

        pipeline.run_analysis(db, batch_id="batch-evidence")

        db.expire_all()
        after = {
            e.event_uid: e.raw_data
            for e in db.query(models.Event).filter(models.Event.batch_id == "batch-evidence").all()
        }

        assert before == after
    finally:
        db.close()
