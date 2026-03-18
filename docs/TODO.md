# TODO

This list is NOT to be read or modified by agents, LLMs, AI, etc.

## Today

- document that i have to use `sudo ./scripts/abnemo.sh monitor --summary-interval 10 --top 9999 --web --web-port 30032 --log-level DEBUG`

- README.md should reference all the docs

- document verification script and link that to DESIGN.md to say why we don't capture all the data

- tests
  - fix tests in the test directory and its subdirectory. no idea which are real tests!
  - run all and check coverage

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

- refactor web_server.py so that it is smaller and multiple files

- test traffic directions

- README.md should describe
  - ABNEMO_CONFIG_DIR
  - how to configure where traffic goes
  - email for warn-list
    - ABNEMO_SMTP_HOST
    - ABNEMO_SMTP_PORT
    - ABNEMO_SMTP_USERNAME
    - ABNEMO_SMTP_PASSWORD
    - ABNEMO_SMTP_FROM
    - ABNEMO_SMTP_TO
    - ABNEMO_SMTP_TLS

- can we do a performance check?

- simplify the code
  - remove code that i don't understand
  - no need for command to read files


## Tomorrow

- BACKUP and restore of iptables!!!!
- is python performance an issue?
- what other products do what this app does and what else do they do?
- docker - see docker md file

## Later