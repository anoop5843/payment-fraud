import json
import os
import logging
import urllib.request
import urllib.error
import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

lambda_client = boto3.client("lambda")
AUTHORIZE_FN = os.environ["AUTHORIZE_FN"]
RISK_URL = os.environ["RISK_URL"]
RISK_TIMEOUT = float(os.environ.get("RISK_TIMEOUT", "3"))
RISK_THRESHOLD = float(os.environ.get("RISK_THRESHOLD", "0.85"))


def lambda_handler(event, context):
    body = event if isinstance(event, dict) and "transaction_id" in event else json.loads(event.get("body", "{}"))
    txn_id = body["transaction_id"]
    amount = float(body["amount"])
    merchant_id = body["merchant_id"]

    try:
        risk = _call_vendor(amount, merchant_id)
    except Exception as e:
        log.exception("risk_vendor_unavailable")
        return _resp(503, {"error": "risk service is unavailable", "txn_id": txn_id})

    if risk["risk_score"] >= RISK_THRESHOLD:
        log.warning(json.dumps({
            "event": "fraud_blocked",
            "txn_id": txn_id,
            "score": risk["risk_score"],
            "provider": risk.get("provider"),
        }))
        return _resp(403, {"error": "blocked by risk policy", "txn_id": txn_id})

    log.info(json.dumps({
        "event": "fraud_passed",
        "txn_id": txn_id,
        "score": risk["risk_score"],
        "provider": risk.get("provider"),
    }))

    body["_risk_score"] = risk["risk_score"]
    body["_risk_provider"] = risk.get("provider")

    resp = lambda_client.invoke(
        FunctionName=AUTHORIZE_FN,
        InvocationType="RequestResponse",
        Payload=json.dumps(body).encode(),
    )
    payload = json.loads(resp["Payload"].read())
    return {"statusCode": payload.get("statusCode", 500), "body": payload.get("body", "{}")}


def _call_vendor(amount, merchant_id):
    url = f"{RISK_URL}/scoress?amount={amount}&merchant_id={merchant_id}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=RISK_TIMEOUT) as resp:
        if resp.status != 200:
            raise RuntimeError(f"vendor status {resp.status}")
        return json.loads(resp.read())


def _resp(status, body):
    return {"statusCode": status, "body": json.dumps(body)}