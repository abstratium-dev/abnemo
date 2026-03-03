#!/usr/bin/env python3
"""
Integration test to verify the timezone bug fix
This test simulates the exact scenario from the bug report
"""

import pytest
import json
import os
import tempfile
import shutil
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_server import get_logs_in_range


class TestTimezoneBugFix:
    """Test that verifies the timezone bug is fixed"""
    
    @pytest.fixture
    def temp_log_dir(self):
        """Create temporary directory for test log files"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def create_log_with_local_time(self, log_dir, local_timestamp_str):
        """Create a log file with local time timestamp (simulating real logs)"""
        filename = f"traffic_log_{local_timestamp_str.replace(':', '').replace('-', '').replace('T', '_')[:15]}.json"
        filepath = os.path.join(log_dir, filename)
        
        log_content = {
            "timestamp": local_timestamp_str,  # Local time, no timezone
            "total_bytes": 1000,
            "total_packets": 10,
            "total_ips": 1,
            "traffic_by_ip": {
                "1.2.3.4": {
                    "bytes": 1000,
                    "packets": 10,
                    "domains": ["example.com"],
                    "ports": [443],
                    "ip_type": "public",
                    "isp": {},
                    "processes": []
                }
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(log_content, f)
        
        return filepath
    
    def test_utc_query_finds_local_time_logs(self, temp_log_dir):
        """
        Test the exact scenario from the bug report:
        - Log file has timestamp in local time (UTC+1): 21:17
        - User queries with UTC time: 20:15 to 20:20
        - Local 21:17 = UTC 20:17, which should be found
        
        This test assumes system is in UTC+1 timezone.
        """
        # Create log with local time 21:17 (which is 20:17 UTC)
        self.create_log_with_local_time(temp_log_dir, "2026-03-02T21:17:00")
        
        # Query with UTC times: 20:15 to 20:20
        begin = datetime(2026, 3, 2, 20, 15, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 20, 20, 0, tzinfo=timezone.utc)
        
        result = get_logs_in_range(temp_log_dir, begin, end)
        
        # Should find the log because 21:17 local = 20:17 UTC
        assert result['files_processed'] == 1, \
            f"Expected 1 file, got {result['files_processed']}. " \
            f"Log at 21:17 local (20:17 UTC) should be within 20:15-20:20 UTC range."
        assert result['total_ips'] == 1
        assert result['total_bytes'] == 1000
    
    def test_utc_query_excludes_out_of_range_local_logs(self, temp_log_dir):
        """
        Test that logs outside the UTC range are correctly excluded
        - Log at local 22:00 (UTC 21:00) should NOT be found
        - Query range: UTC 20:15 to 20:20
        """
        # Create log at local 22:00 (which is 21:00 UTC, outside range)
        self.create_log_with_local_time(temp_log_dir, "2026-03-02T22:00:00")
        
        # Query with UTC times: 20:15 to 20:20
        begin = datetime(2026, 3, 2, 20, 15, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 20, 20, 0, tzinfo=timezone.utc)
        
        result = get_logs_in_range(temp_log_dir, begin, end)
        
        # Should NOT find the log
        assert result['files_processed'] == 0, \
            f"Expected 0 files, got {result['files_processed']}. " \
            f"Log at 22:00 local (21:00 UTC) should be outside 20:15-20:20 UTC range."
    
    def test_multiple_logs_correct_filtering(self, temp_log_dir):
        """
        Test with multiple logs, some in range and some out of range
        """
        # Create logs at different local times
        self.create_log_with_local_time(temp_log_dir, "2026-03-02T21:10:00")  # 20:10 UTC - in range
        self.create_log_with_local_time(temp_log_dir, "2026-03-02T21:18:00")  # 20:18 UTC - in range
        self.create_log_with_local_time(temp_log_dir, "2026-03-02T21:25:00")  # 20:25 UTC - out of range
        self.create_log_with_local_time(temp_log_dir, "2026-03-02T20:00:00")  # 19:00 UTC - out of range
        
        # Query with UTC times: 20:15 to 20:20
        begin = datetime(2026, 3, 2, 20, 15, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 20, 20, 0, tzinfo=timezone.utc)
        
        result = get_logs_in_range(temp_log_dir, begin, end)
        
        # Should find only the log at 21:18 (20:18 UTC)
        # Note: 21:10 local = 20:10 UTC, which is before 20:15 UTC
        assert result['files_processed'] == 1, \
            f"Expected 1 file in range, got {result['files_processed']}"
    
    def test_url_encoded_timestamp_parsing(self, temp_log_dir):
        """
        Test with URL-encoded timestamp format from the bug report
        URL: ?begin=2026-03-02T20%3A15%3A42.000Z&end=2026-03-02T20%3A20%3A42.000Z
        Decoded: begin=2026-03-02T20:15:42.000Z&end=2026-03-02T20:20:42.000Z
        """
        # Create log at local 21:17 (20:17 UTC)
        self.create_log_with_local_time(temp_log_dir, "2026-03-02T21:17:42.123456")
        
        # Parse timestamps as they would come from URL (with Z suffix)
        begin_str = "2026-03-02T20:15:42.000Z"
        end_str = "2026-03-02T20:20:42.000Z"
        
        begin = datetime.fromisoformat(begin_str.replace('Z', '+00:00'))
        end = datetime.fromisoformat(end_str.replace('Z', '+00:00'))
        
        # Ensure they're in UTC
        begin = begin.astimezone(timezone.utc)
        end = end.astimezone(timezone.utc)
        
        result = get_logs_in_range(temp_log_dir, begin, end)
        
        # Should find the log
        assert result['files_processed'] == 1
        assert result['total_bytes'] == 1000


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
