from dataclasses import dataclass


@dataclass(frozen=True)
class DecoyResource:
    path: str
    title: str
    content_type: str
    synthetic: bool = True


DECOYS = {
    "/admin/credentials": DecoyResource("/admin/credentials", "Legacy service credentials", "application/json"),
    "/files/confidential/Finance_2026/legacy-service.json": DecoyResource("/files/confidential/Finance_2026/legacy-service.json", "legacy-service.json", "application/json"),
}


def decoy_payload(resource: DecoyResource) -> dict[str, object]:
    return {"synthetic": True, "resource": resource.title, "service_account": "svc-finance-export", "api_key": "IG_DECOY_ONLY_NOT_A_REAL_SECRET", "created_at": "2026-06-14T09:12:00Z"}
