"""AWS CloudTrail emitter.

Renders `Event`s carrying a `cloud` payload as newline-delimited JSON
records approximating an AWS CloudTrail log file (the same shape you'd
get from a CloudTrail S3 export or `aws cloudtrail lookup-events`):
`eventVersion`, `eventTime`, `eventSource`, `eventName`, `awsRegion`,
`sourceIPAddress`, `userAgent`, `userIdentity`, and `errorCode` on
non-OK calls.

Only the fields the shared `CloudApiCall` model carries are populated —
a representative subset of a real CloudTrail record, not a byte-for-byte
schema match (real CloudTrail records carry many more optional fields
depending on the API called).
"""

from __future__ import annotations

import json

from forge_incident.emitters.base import EmittedArtifact, Emitter, iso8601_z_timestamp, stable_hex_id
from forge_incident.models import LogSource, Scenario

__all__ = ["AwsCloudTrailEmitter"]


class AwsCloudTrailEmitter(Emitter):
    log_source = LogSource.AWS_CLOUDTRAIL

    def emit(self, scenario: Scenario) -> list[EmittedArtifact]:
        events = [e for e in self.relevant_events(scenario) if e.cloud is not None]
        if not events:
            return []

        account_id = scenario.organization.gcp_project_id or "000000000000"
        lines: list[str] = []

        for event in events:
            cloud = event.cloud
            assert cloud is not None
            principal = scenario.get_actor(event.actor).email if event.actor else "unknown"

            record = {
                "eventVersion": "1.09",
                "eventTime": iso8601_z_timestamp(event.timestamp),
                "eventID": stable_hex_id(event.event_id, "aws_cloudtrail", "eventID", length=36),
                "eventSource": cloud.service_name,
                "eventName": cloud.method_name,
                "awsRegion": cloud.region or "us-east-1",
                "sourceIPAddress": cloud.caller_ip,
                "userAgent": cloud.user_agent or "aws-cli/2.15.0",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": stable_hex_id(principal, "aws", "principalId", length=21).upper(),
                    "arn": f"arn:aws:iam::{account_id}:user/{principal}",
                    "accountId": account_id,
                    "userName": principal,
                },
                "requestParameters": {"resourceName": cloud.resource_name},
                "responseElements": None,
                "recipientAccountId": account_id,
                **(
                    {}
                    if cloud.status_code == "OK"
                    else {"errorCode": cloud.status_code, "errorMessage": cloud.status_code}
                ),
            }
            lines.append(json.dumps(record, separators=(",", ":")))

        content = "\n".join(lines) + "\n"
        return [
            EmittedArtifact(
                relative_path=f"logs/aws_cloudtrail/{account_id}-cloudtrail.jsonl",
                content=content,
                description=(
                    f"AWS CloudTrail export ({len(events)} entries) for account "
                    f"{account_id}, JSON Lines format."
                ),
            )
        ]
