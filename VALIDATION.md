# Linux Lab Validation

Run these commands on the Linux host where srsUE owns the IMS APN interface.

## 1. Prepare

```bash
python3 -m pip install -r requirements.txt
```

Edit `config/demo.yaml`:

- `network.interface`
- `network.pcscf_ip`
- `subscriber.imsi`
- `subscriber.impi`
- `subscriber.impu`
- `subscriber.realm`
- `subscriber.k`
- `subscriber.opc`
- `call.target_uri`

Keep this disabled for the first pass:

```yaml
debug:
  execute_xfrm_commands: false
```

## 2. Configuration Summary

```bash
python3 main.py --config config/demo.yaml --mode summary
```

Expected: the client prints interface, P-CSCF, subscriber, target, media, and
XFRM dry-run status.

## 3. Offline Unit Tests

```bash
python -m pytest
```

Expected: parser, digest, SDP, RTP, AMR-WB, AKA nonce split, and XFRM command
tests pass.

## 4. Network Check

```bash
python3 main.py --config config/demo.yaml --mode network-check
```

Expected:

- IMS APN IPv4 is logged.
- `ip route get <pcscf_ip>` uses the configured interface.
- TCP connect to the P-CSCF succeeds from the IMS IP.

## 5. Initial REGISTER And Dry-Run XFRM

```bash
python3 main.py --config config/demo.yaml --mode register --log-level DEBUG
```

Expected:

- Initial REGISTER is sent.
- 401 Unauthorized is received.
- `WWW-Authenticate` nonce is decoded into RAND/AUTN.
- AKA computes RES, CK, IK.
- `Security-Server` is parsed.
- XFRM state/policy commands are printed as dry-run.
- The client stops before protected REGISTER because XFRM execution is disabled.

## 6. Protected REGISTER

Only after checking SPI direction, ports, and selectors against a real capture:

```yaml
debug:
  execute_xfrm_commands: true
```

Then run:

```bash
sudo python3 main.py --config config/demo.yaml --mode register --log-level DEBUG
```

Expected:

- `ip -s xfrm state` and `ip -s xfrm policy` show the generated entries.
- For `Security-Server` with `alg=hmac-md5-96` and `ealg=null`, generated state commands should use `auth-trunc hmac(md5) 0x... 96 enc ecb(cipher_null) ""`.
- The second REGISTER is sent through ESP.
- IMS returns 200 OK for REGISTER.

## 7. Call And Media

Prepare `media_files/send.amr` as AMR-WB 16 kHz mono:

```bash
ffmpeg -y -i input.wav -ar 16000 -ac 1 -c:a libvo_amrwbenc media_files/send.amr
```

Then run:

```bash
sudo python3 main.py --config config/demo.yaml --mode call --duration-seconds 30 --log-level DEBUG
```

Use `--duration-seconds 0` to loop `media_files/send.amr` until remote BYE,
Ctrl+C, or SIGTERM.

Expected:

- INVITE reaches the target IMPU.
- The client waits up to `call.setup_timeout_seconds` for 18x/200 INVITE responses while the target rings.
- 183 with SDP triggers PRACK if RSeq is present.
- 200 INVITE triggers ACK.
- RTP AMR-WB is sent every 20 ms.
- Remote RTP is saved to `media_files/received.amr`.
- BYE is sent after `--duration-seconds`. If the option is omitted, the default is 30 seconds. If the effective duration is `<= 0`, media runs until remote BYE or signal.

Convert received audio:

```bash
ffmpeg -y -i media_files/received.amr received.wav
```

## 8. Listen Mode

Register and wait for an inbound call:

```bash
sudo python3 main.py --config config/demo.yaml --mode listen --log-level DEBUG
```

Expected:

- Protected SIP connection is established and the client logs that it is waiting for inbound calls.
- On inbound INVITE, the client sends 180 Ringing.
- After a random 1-5 second delay, the client sends 200 OK with local AMR-WB SDP.
- After ACK, RTP starts: `send.amr` is looped and remote audio is saved to `media_files/received.amr`.
- Ctrl+C/SIGTERM or remote BYE stops RTP, drains SIP briefly, closes sockets, cleans XFRM, and stops pcap capture.
