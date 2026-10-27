import unittest
from app import analyze, parse_asc, parse_csv, payload

class AnalyzerTests(unittest.TestCase):
    def test_payload_parsing(self):
        self.assertEqual(payload("10 27 00 FF"), [16, 39, 0, 255])
        self.assertEqual(payload("102700FF"), [16, 39, 0, 255])

    def test_csv_trace_and_inventory(self):
        frames = parse_csv("timestamp,can_id,dlc,data\n0.0,0x100,2,10 00\n0.01,0x100,2,20 00\n")
        result = analyze(frames, {"signals": [{"name":"Raw","can_id":"0x100","start_byte":0,"length":1,"scale":2,"offset":0}]})
        self.assertEqual(result["summary"]["frames"], 2)
        self.assertEqual(result["summary"]["unique_ids"], 1)
        self.assertEqual([p["value"] for p in result["signals"][0]["points"]], [32, 64])

    def test_timeout_detection_requires_config(self):
        frames = parse_csv("timestamp,can_id,dlc,data\n0.0,0x100,1,01\n0.1,0x100,1,02\n")
        no_rule = analyze(frames, {})
        with_rule = analyze(frames, {"timeouts":[{"can_id":"0x100","period_ms":10,"multiplier":2}]})
        self.assertEqual(no_rule["summary"]["events"], 0)
        self.assertEqual(with_rule["summary"]["error_events"], 1)

    def test_common_asc_line(self):
        frames = parse_asc("date Mon Jan 01 00:00:00.000 AM 2024\n0.010000 1 100 Rx d 2 11 22\n")
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["can_id"], 0x100)
        self.assertEqual(frames[0]["data"], [0x11, 0x22])

if __name__ == "__main__":
    unittest.main()
