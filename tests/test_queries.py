from datetime import datetime, timedelta

from hunter.queries import (
    hunt_beaconing,
    hunt_offhours_logons,
    hunt_password_spray,
    hunt_rare_ports,
)

BASE = datetime(2026, 9, 20, 0, 0, 0)


def _flow(t, src, dst, port, out_b=100, in_b=100):
    return {"ts": t, "duration_s": 1, "src_ip": src, "dst_ip": dst,
            "dst_port": port, "proto": "tcp", "bytes_out": out_b, "bytes_in": in_b}


def test_beacon_detected():
    flows = [_flow(BASE + timedelta(seconds=60 * i), "10.0.0.5", "203.0.113.9", 443)
             for i in range(30)]
    # Add irregular noise flows so the dataset is realistic.
    flows += [_flow(BASE + timedelta(minutes=i * 3), "10.0.0.6", "93.184.216.34", 80)
              for i in range(10)]
    f = hunt_beaconing(flows)
    assert len(f) == 1
    assert f[0]["evidence"]["src_ip"] == "10.0.0.5"
    assert f[0]["severity"] == "likely-malicious"


def test_no_beacon_on_irregular_traffic():
    flows = [_flow(BASE + timedelta(minutes=i * (1 + i % 5)), "10.0.0.5", "93.184.216.34", 443)
             for i in range(40)]
    assert hunt_beaconing(flows) == []


def test_rare_port_detected():
    flows = [_flow(BASE + timedelta(minutes=i), "10.0.0.5", "93.184.216.34", 443)
             for i in range(500)]
    flows.append(_flow(BASE + timedelta(minutes=5), "10.0.0.5", "198.51.100.99", 54321))
    f = hunt_rare_ports(flows)
    assert any(x["evidence"]["dst_port"] == 54321 for x in f)


def test_offhours_logon_detected():
    auth = [
        {"ts": BASE + timedelta(hours=2, minutes=13), "user": "jpark",
         "src_ip": "10.0.0.5", "success": True, "method": "password"},
        {"ts": BASE + timedelta(hours=10), "user": "osama",
         "src_ip": "10.0.0.6", "success": True, "method": "password"},
    ]
    f = hunt_offhours_logons(auth)
    assert len(f) == 1
    assert f[0]["evidence"]["user"] == "jpark"


def test_password_spray_detected():
    auth = [
        {"ts": BASE + timedelta(seconds=10 * i), "user": f"user{i}",
         "src_ip": "198.51.100.7", "success": False, "method": "password"}
        for i in range(4)
    ]
    f = hunt_password_spray(auth)
    assert len(f) == 1
    assert f[0]["evidence"]["attempts"] == 4
