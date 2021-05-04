Gets weak cipher usage (RC4 used in Domain environments). useful for On-Prem diagnostics, similar to MDI (cloud app sec) weak cupher usage report.

By default, queries all Domain Controllers' Security events logs (requires Event Log Readers or equivalent/DA).

OPTIONAL: Can limit events from a certain Time and Date (need to specify both optional parameters), for shorter execution and avoid query overload in large environments/large Security Logs.

OPTIONAL: If using an Event Forwarder to log 4769 (Kerberos TGS events) from all DCs - can also specify an Event Forwarding server.
