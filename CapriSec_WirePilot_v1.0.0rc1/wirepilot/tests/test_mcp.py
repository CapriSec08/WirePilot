import asyncio
import json
import os
import shutil
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from make_fixture import write_fixture
from scenarios import ctf_capture


def test_stdio_protocol_and_case_persistence(tmp_path):
    captures = tmp_path / "captures"
    captures.mkdir()
    write_fixture(captures / "test.pcap")
    ctf_capture(captures / "ctf.pcap")
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    (incoming / "events.jsonl").write_text(
        json.dumps(
            {
                "time": 1760000000,
                "source": "10.0.0.10",
                "destination": "10.0.0.20",
                "kind": "lab",
                "description": "Synthetic observation",
            }
        )
        + "\n"
    )
    env = dict(
        os.environ,
        WIREPILOT_CAPTURE_ROOT=str(captures),
        WIREPILOT_STATE_ROOT=str(tmp_path / "state"),
        WIREPILOT_IMPORT_ROOT=str(incoming),
        WIREPILOT_ALLOW_PAYLOAD="1",
    )
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "wirepilot.server"], env=env
    )

    async def run():
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer) as client:
                await client.initialize()
                listing = await client.list_tools()
                assert len(listing.tools) == 44
                assert len((await client.list_prompts()).prompts) == 4
                assert len((await client.list_resources()).resources) == 1

                async def call(name, args={}):
                    result = await client.call_tool(name, args)
                    assert not result.isError, result
                    return result.structuredContent

                health = await call("health_check")
                assert health["version"] == "1.0.0rc1"
                inventory = await call("discover_network_tools")
                assert any(t["name"] == "tcpdump" for t in inventory["tools"])
                assert (await call("list_capture_files"))["total"] == 2
                assert (
                    await call(
                        "decode_text", {"text": "ZmxhZw==", "encoding": "base64"}
                    )
                )["text"] == "flag"
                imported = await call(
                    "import_network_events",
                    {"path": "events.jsonl", "format": "network"},
                )
                assert (
                    await call("get_network_events", {"event_id": imported["event_id"]})
                )["events"]
                cap = await call("register_capture", {"path": "test.pcap"})
                case = await call("create_case", {"title": "Synthetic investigation"})
                case_id = case["case_id"]
                await call(
                    "attach_capture",
                    {"case_id": case_id, "capture_id": cap["capture_id"]},
                )
                await call(
                    "add_case_note",
                    {"case_id": case_id, "note": "Synthetic data only."},
                )
                assert (await call("get_case", {"case_id": case_id}))["note_count"] == 1
                assert (await call("list_cases"))["cases"][0]["id"] == case_id
                assert (await call("read_case_notes", {"case_id": case_id}))["notes"]
                error = await client.call_tool(
                    "register_capture", {"path": "../outside.pcap"}
                )
                assert error.isError
                if shutil.which(os.environ.get("WIREPILOT_TSHARK", "tshark")):
                    args = {"capture_id": cap["capture_id"]}
                    overview = await call("capture_overview", args)
                    assert overview["summary"]["packets"] == 44
                    diagnosis = await call("diagnose_connectivity", args)
                    assert {"DNS_ERROR", "TCP_REFUSED", "HTTP_ERROR"} <= {
                        f["rule_id"] for f in diagnosis["findings"]
                    }
                    detection = await call("detect_anomalies", args)
                    assert {
                        "SYN_FANOUT",
                        "PERIODIC_CONNECTIONS",
                        "ARP_MAPPING_CHANGE",
                    } <= {f["rule_id"] for f in detection["findings"]}
                    await call("list_conversations", args)
                    await call("inspect_protocol", {**args, "protocol": "dns"})
                    await call(
                        "query_packets",
                        {**args, "display_filter": "http.response.code == 503"},
                    )
                    await call("assess_ransomware_indicators", args)
                    for name in (
                        "investigate_pcap",
                        "analyse_authentication",
                        "analyse_network_engineering",
                        "get_timeline",
                    ):
                        assert (await call(name, args))["coverage"][
                            "capture_id"
                        ] == cap["capture_id"]
                    assert (
                        await call(
                            "query_packet_range",
                            {**args, "start_frame": 20, "frame_count": 5},
                        )
                    )["packets"][0]["frame.number"] == "20"
                    assert (await call("packet_details", {**args, "frame_number": 1}))[
                        "packets"
                    ]
                    assert (
                        await call(
                            "find_protocol_fields", {"query": "http.response.code"}
                        )
                    )["fields"]
                    assert (
                        await call(
                            "query_protocol_fields",
                            {
                                **args,
                                "fields": ["http.response.code"],
                                "display_filter": "http.response.code == 503",
                            },
                        )
                    )["packets"]
                    rejected = await client.call_tool(
                        "query_protocol_fields",
                        {**args, "fields": ["not_a_real_field"]},
                    )
                    assert rejected.isError
                    assert (
                        await call(
                            "compare_captures",
                            {**args, "baseline_capture_id": cap["capture_id"]},
                        )
                    )["new_hosts"] == []
                    await call(
                        "correlate_network_events",
                        {**args, "event_id": imported["event_id"]},
                    )
                    ctf_cap = await call("register_capture", {"path": "ctf.pcap"})
                    assert (
                        await call(
                            "search_capture_text",
                            {"capture_id": ctf_cap["capture_id"], "stream_id": 0},
                        )
                    )["matches"]
                    assert (
                        await call(
                            "inspect_credentials",
                            {"capture_id": ctf_cap["capture_id"], "stream_id": 0},
                        )
                    )["credentials"]
                    assert (
                        await call(
                            "export_http_objects",
                            {"capture_id": ctf_cap["capture_id"], "stream_id": 0},
                        )
                    )["objects"]
                    assert (
                        await call(
                            "hunt_indicators", {**args, "indicators": ["example.test"]}
                        )
                    )["total_matches"] >= 2
                    report = await call(
                        "export_report",
                        {"case_id": case_id, "event_id": imported["event_id"], **args},
                    )
                    with open(report["json_path"]) as stream:
                        saved = json.load(stream)
                        assert saved["coverage"]["sha256"] == cap["sha256"]
                        assert (
                            saved["external_evidence"]["event_id"]
                            == imported["event_id"]
                        )
        # New process: the case, note and evidence references must survive restart.
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer) as client:
                await client.initialize()
                result = await client.call_tool("get_case", {"case_id": case_id})
                assert result.structuredContent["note_count"] == 1
                assert result.structuredContent["capture_count"] == 1

    asyncio.run(run())
