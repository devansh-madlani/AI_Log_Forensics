"""
Convenience CLI: load the synthetic demo dataset and immediately run
analysis on it, printing a summary. Useful for a quick sanity check
before a live demo, without needing curl/Postman.

Usage:
    python run_demo.py
    python run_demo.py --events 200
"""

import argparse
import sys

from app.database import init_db, SessionLocal
from app import pipeline
from app.demo.synthetic_data import generate as generate_demo_events


def main():
    parser = argparse.ArgumentParser(description="Load demo data and run the forensic analysis pipeline.")
    parser.add_argument("--events", type=int, default=140, help="Number of normal background events to generate")
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
    try:
        print(f"Generating synthetic demo dataset ({args.events} normal events + injected attack storyline)...")
        raw_events = generate_demo_events(num_normal_events=args.events)
        print(f"Generated {len(raw_events)} raw synthetic events (all tagged DEMO/SYNTHETIC).")

        ingest_result = pipeline.ingest_raw_events(db, raw_events, batch_id=pipeline.new_batch_id("demo-cli"))
        print(f"Ingested + normalized: {ingest_result}")

        analysis_result = pipeline.run_analysis(db, batch_id=ingest_result["batch_id"])
        print(f"Analysis complete: {analysis_result}")

        print("\nDone. Start the API (uvicorn app.main:app --reload) and open the")
        print("dashboard to explore the results, or query directly, e.g.:")
        print("  curl http://127.0.0.1:8000/stats")
        print("  curl http://127.0.0.1:8000/events/suspicious")
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
