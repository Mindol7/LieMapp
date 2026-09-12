"""Archive official public metadata sources; never execute imported requests/scripts.

Only fixed HTTPS documentation/source URLs are fetched. Existing provenance is
verified offline, not replaced. No API keys, accounts or paid endpoints are used.
"""

import datetime
import hashlib
import json
import os
from pathlib import Path
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parent
REVISION = "942d1390f81ee4e2cb7d84913b181d5dafe8b2cc"
GITHUB = f"https://raw.githubusercontent.com/postmanlabs/newman/{REVISION}"
PLATFORM_URL = "https://www.postman.com/postman/published-postman-templates/request/veqiyus/get-request"
COLLECTION_URL = "https://www.postman.com/postman/published-postman-templates/documentation/ae2ja6x/postman-echo?ctx=documentation"
SOURCES = (
    ("sources/official-newman-echo-v2.collection.json",
     GITHUB + "/test/integration/echo-v2.postman_collection.json",
     "27a09d5666463ed759b47a9a6146237993fd2e097d17949bb6ab21f87e9b68bd"),
    ("sources/official-newman-LICENSE.md", GITHUB + "/LICENSE.md",
     "0cadd34c6ab73fe2451fe7e60717f28ded000b6d9e0c7eeae094be94f8b97602"),
    ("sources/provider-echo-docs.md",
     "https://learning.postman.com/docs/reference/developer-resources/echo-api.md",
     "b90103f0ee2fd12105774a3cc40080bc0eb90a2a312e79fb85859e7f5031a4c7"),
    ("sources/public-get-listing-shell.html", PLATFORM_URL, None),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_new(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def verify(manifest):
    if manifest["operation"]["endpoint"] != "https://postman-echo.com/get":
        raise ValueError("Unexpected operation endpoint")
    if manifest["operation"]["method"] != "GET":
        raise ValueError("Unexpected operation method")
    seen = set()
    for entry in manifest["files"]:
        path = ROOT / entry["path"]
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT) or path in seen:
            raise ValueError("Unsafe or duplicate source path")
        seen.add(path)
        data = path.read_bytes()
        if len(data) != entry["bytes"] or digest(data) != entry["sha256"]:
            raise ValueError(f"Source bytes changed: {entry['path']}")
    return manifest


def main():
    manifest_path = ROOT / "provenance.json"
    if manifest_path.exists() or manifest_path.is_symlink():
        if manifest_path.is_symlink():
            raise ValueError("Refusing symlink provenance")
        verify(json.loads(manifest_path.read_text()))
        print("Existing provenance and source files verified offline; no downloads.")
        return
    if any((ROOT / name).exists() or (ROOT / name).is_symlink() for name, _, _ in SOURCES):
        raise ValueError("Partial source capture exists; preserve it and review before retrying")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError("Source redirects are not accepted; inspect changed official URL first")

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    acquired = []
    for name, url, expected_hash in SOURCES:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in {
            "raw.githubusercontent.com", "learning.postman.com", "www.postman.com"
        }:
            raise ValueError("Unexpected source host")
        request = urllib.request.Request(url, headers={
            "User-Agent": "LieMapp-source-provenance/1.0", "Accept-Encoding": "identity"
        })
        with opener.open(request, timeout=30) as response:
            data = response.read(2_000_001)
            if response.status != 200 or len(data) > 2_000_000:
                raise ValueError("Unexpected source status/size")
            details = {
                "path": name, "bytes": len(data), "sha256": digest(data),
                "source_url": url, "retrieved_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "http_status": response.status,
                "response_headers": {k: response.headers[k] for k in
                    ("Content-Type", "Date", "ETag", "Last-Modified", "Content-Length")
                    if response.headers.get(k) is not None},
            }
        if expected_hash is not None and digest(data) != expected_hash:
            raise ValueError(f"Pinned source hash mismatch: {name}")
        acquired.append((details, data))

    collection = json.loads(acquired[0][1])
    original = collection["item"][4]["item"][0]
    request = original["request"]
    if (original["id"] != "e9f4387b-5b32-ae3c-cae3-f8470d1c6b1f"
            or request["method"] != "GET"
            or request["url"] != "https://postman-echo.com/get?test=123"):
        raise ValueError("Pinned collection operation changed")
    docs = acquired[2][1].decode()
    if "https://postman-echo.com/get" not in docs or "ae2ja6x/postman-echo" not in docs:
        raise ValueError("Official provider docs no longer link the API and public collection")

    manifest = {
        "schema_version": "1.0.0",
        "source_id": "postman-echo-public-get-v1",
        "operation": {
            "method": "GET", "endpoint": "https://postman-echo.com/get",
            "platform": "Postman Public API Network", "platform_url": PLATFORM_URL,
            "provider": "Postman", "public_collection_url": COLLECTION_URL,
            "public_listing_query_examples": [{"key": "foo1", "value": "bar1"}, {"key": "foo2", "value": "bar2"}],
            "query_examples_evidence": "Public listing as rendered by the research web reader; not a downloaded JSON export. The archived live HTML is an application shell, not the rendered field content.",
            "query_contract": "GET /get reflects supplied query key/value strings under response.args; foo1/foo2 are example names, not authenticated credentials or required provider fields.",
            "authentication": "No authentication for this GET test endpoint; authorization test endpoints elsewhere in the collection are excluded.",
            "provider_malicious": False, "attacker_owned_endpoint": False,
        },
        "metadata_import": {
            "kind": "official_github_collection_snapshot",
            "repository": "https://github.com/postmanlabs/newman", "commit": REVISION,
            "source_file": SOURCES[0][0], "collection_name": collection["info"]["name"],
            "collection_id": collection["info"]["_postman_id"],
            "json_pointer": "/item/4/item/0", "item_id": original["id"],
            "original_name": original["name"], "original_request": request,
            "is_current_public_platform_export": False,
            "explanation": "공개 플랫폼의 Echo API 등록과 실제 메타데이터 수입 경로를 구분한다. 파일은 Postman의 공식 GitHub 고정 커밋 자료이며, 현재 공개 컬렉션을 직접 내보낸 JSON과 동일하다고 검증하지 않았다. 원본 GET 예시는 test=123이고 공개 페이지 예시는 foo1=bar1&foo2=bar2이다. 원본에 들어 있는 테스트 스크립트·인증 예제·GET body는 실행하지 않는다.",
        },
        "platform_origin_evidence": {
            "provider_docs_file": SOURCES[2][0],
            "public_listing_file": SOURCES[3][0],
            "listing_capture_kind": "live_http_200_application_shell_only",
            "live_provider_docs_link_to_public_collection": True,
            "public_get_documentation_url": "https://www.postman.com/postman/published-postman-templates/documentation/ucvy59g/postman-echo?entity=request-33232-8be8263c-7451-485e-a587-15772abba9c0",
            "rendered_get_item_reference": "33232-8be8263c-7451-485e-a587-15772abba9c0",
            "rendered_collection_reference": "33232-4172eede-4afb-4704-9a5a-436cc0634195",
            "identity_limit": "Rendered request/documentation and provider-linked public collection may be different official collection copies. Their UUIDs are not merged with the GitHub collection UUID.",
        },
        "local_adapters": {
            "authored_separately": True,
            "explanation": "LLM 도구 이름·설명·필수 인자 제약 및 정상/공격 역할은 로컬 실험 어댑터가 정의한다. 이를 Postman 원본 메타데이터나 Postman이 악성이라는 증거로 표시하지 않는다.",
            "allowed_external_operation": "GET https://postman-echo.com/get only",
            "all_values_synthetic": True, "api_credentials_required": False,
            "imported_scripts_executed": False,
        },
        "usage_limits_and_scope": {
            "echo_specific_numeric_rate_limit_verified": False,
            "rate_limit_note": "Postman account API 300/min and mock-server 120/min limits are not Echo limits. Use a small sequential predeclared request budget, honor 429/Retry-After, and stop rather than retry aggressively.",
            "service_terms_url": "https://www.postman.com/legal/terms/",
            "acceptable_use_url": "https://www.postman.com/legal/postman-acceptable-use-policy/",
            "terms_review_limit": "Current legal pages load contract text dynamically; full current contract text was not retrieved by this bounded review. Official Echo docs explicitly describe request testing. No assertion of unlimited usage, SLA, legal clearance, or absence of provider logging is made.",
            "no_paid_calls_or_accounts": True,
            "no_actual_api_calls_in_source_import": True,
            "receipt_limit": "An authenticated HTTPS Echo response reflecting a fresh synthetic argument supports external receipt by the service; it does not establish attacker ownership, actual personal-data theft, or independent server audit logs.",
        },
        "files": [details for details, _ in acquired],
    }
    for details, data in acquired:
        write_new(ROOT / details["path"], data)
    write_new(manifest_path, encode(manifest))
    verify(manifest)
    print("Archived 4 official sources and provenance.json; no API operation executed.")


if __name__ == "__main__":
    main()
