#!/usr/bin/env python3
import argparse
import json
import time

import requests

from modules import onering, parse, test_xray
from utils import helpers


def run_job(job):
    url = job.get("url", "")
    targets = job.get("targets", [])
    if not url or not targets:
        return []

    account = parse.parse_vmess_trojan_url(url)
    modes = {
        "1": "Address",
        "2": "Wildcard",
        "3": "SNI",
        "4": "Onering",
    }
    results = []
    for target in targets:
        for m in ("1", "2", "3", "4"):
            mode_name = modes[m]
            try:
                helpers.kill_xray_processes()
            except Exception:
                pass
            success = False
            error = None
            try:
                if m == "4":
                    success, _ = onering.test_onering(target, account)
                elif m == "2":
                    success = test_xray.test_wildcard_address(target, account)
                elif m == "3":
                    success = test_xray.test_address(None, account, target)
                elif m == "1":
                    success = test_xray.test_address(target, account)
            except Exception as exc:
                error = str(exc)
            results.append(
                {
                    "target": target,
                    "mode": mode_name,
                    "success": success,
                    "error": error,
                }
            )
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--api-key", required=True)
    args = parser.parse_args()

    server = args.server.rstrip("/")
    api_key = args.api_key

    while True:
        try:
            resp = requests.post(f"{server}/api/agent/poll", data={"api_key": api_key}, timeout=30)
            job = resp.json().get("job")
            if not job:
                time.sleep(5)
                continue
            results = run_job(job)
            requests.post(
                f"{server}/api/agent/report",
                data={
                    "api_key": api_key,
                    "job_id": job.get("job_id"),
                    "results": json.dumps(results),
                },
                timeout=60,
            )
        except Exception:
            time.sleep(5)


if __name__ == "__main__":
    main()
