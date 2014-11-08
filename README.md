goal is to carve out the Tcp reader from [heka's TcpInput module](https://github.com/mozilla-services/heka/blob/dev/plugins/tcp/tcp_input.go#L190) and try to narrow down the case where [tls.(*Conn).SetReadDeadline spun out of control](http://f.cl.ly/items/0y0E0Q2f1m1q0u0H3D0y/heka_cpu_burn.svg).

```toml
[hekad]
maxprocs = 3
base_dir = "/data/appdata/heka-tls"
cpuprof = "/tmp/heka-tls.prof"

[syslog_tls_dec]
type = "MultiDecoder"
subs = ["RsyslogDecoder", "session_scribble"]
cascade_strategy = "all"
log_sub_errors = true

[syslog_tls]
type = "TcpInput"
address = "0.0.0.0:5114"
decoder = "syslog_tls_dec"
parser_type = "token"
use_tls = true

[syslog_tls.tls]
cert_file = "/data/secure/ssl/pem.pem"
key_file = "/data/secure/ssl/key.key"
prefer_server_ciphers = true

[boundary_session_sync_decoder]
type = "MultiDecoder"
cascade_strategy = "all"
log_sub_errors = true
subs = ['ProtobufDecoder', 'boundary_scribble']
[ProtobufDecoder]

[boundary_scribble]
type = "ScribbleDecoder"
    [boundary_scribble.message_fields]
    Type = "boundary_haproxy"
    Logger = "sessions"
