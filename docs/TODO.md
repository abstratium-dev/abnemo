# TODO

This list is NOT to be read or modified by agents, LLMs, AI, etc.

## Today

- document that i have to use `sudo ./scripts/abnemo.sh monitor --enable-process-tracking --summary-interval 10 --top 9999 --ebpf --web --web-port 30032 --isp-debug`
- README.md should reference all the docs
- BACKUP and restore of iptables!!!!
- tests
  - fix tests in the test directory and its subdirectory. no idea which are real tests!
  - run all and check coverage
- what other products do this?
- install as service so it's restarted if it crashes
  - read SYSTEMD_SERVICE.md
- ips
  - whitelist with regex
  - ban an ip address permanently
  - unban an ip address
  - list banned ip addresses
- alerting if there are sudden spikes in traffic
- graph showing traffic over time, based on logs, so interval isn't very large which is ok for this tool
- use mermaid for diagrams in docs
- create SBOM
- what other legal requirements are there?
- test traffic directions
- read and verify: VERIFICATION_GUIDE.md
  - write a program that does this verification for us
- can we do a performance check?
- what is enable_process_tracking and do we still need it?
- simplify the code
  - always require ebpf
  - remove code that i don't understand
  - no need for command to read files


## Tomorrow

- is python performance an issue?
- run this in docker? how could it access the host?

## Later