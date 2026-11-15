#!/bin/bash
# packaging/privacy/isolated-test.sh TARGET_DIR [labyrinth|lykanos]: the private microphone end to end, in a PipeWire and WirePlumber of its
# own, never the desktop's: own runtime, config, state and data folders, no D-Bus, no ALSA/Bluetooth/camera monitors.
# A fake device microphone is fed synthetic room noise with 60 Hz mains hum; two recordings (the default input, and one
# that asks for the device microphone by name) must both come from the private microphone, the device microphone must be
# invisible to clients and refuse a manual link, and the recordings must have no mains hum (ENF) left.
# Sarina's voice input (a stream marked heimdall.private-mic.exempt = "sarina-voice") records the private microphone; only
# as lykanos (its fragment installed, as os-setup links it there) and with heimdall.private-mic.sarina-raw on does it get
# the device microphone, and every other recording stays private. As labyrinth the setting does not exist.
#
# TARGET_DIR holds release builds of heimdall-scrub, heimdall-private-mic and libheimdall_scrub_ladspa.so
# (cd rust && cargo build --release -p heimdall-scrub -p heimdall-scrub-ladspa). Needs pipewire, wireplumber, ffmpeg.
# Takes about a minute. Exit 0 = every check passed.
set -u
REL=$(realpath "${1:?usage: isolated-test.sh TARGET_DIR [labyrinth|lykanos]}")
OS=${2:-labyrinth}
H=$(cd "$(dirname "$0")/../.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-mic-test.XXXXXX")
# a socket path must stay under 108 bytes
RUN=$(mktemp -d /tmp/hpm.XXXXXX)
fail=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }

mkdir -p "$T"/{config/wireplumber/wireplumber.conf.d,state,data/wireplumber/scripts/heimdall,pwconf/pipewire.conf.d,ladspa,out}
ln -s "$REL/libheimdall_scrub_ladspa.so" "$T/ladspa/heimdall-scrub.so"
cat > "$T/pwconf/pipewire.conf" <<'EOF'
context.properties = { core.daemon = true core.name = pipewire-0 default.clock.rate = 48000
                       default.clock.quantum = 1024 mem.allow-mlock = false log.level = 2 }
context.spa-libs = { audio.convert.* = audioconvert/libspa-audioconvert support.* = support/libspa-support }
context.modules = [
    { name = libpipewire-module-protocol-native } { name = libpipewire-module-metadata }
    { name = libpipewire-module-spa-device-factory } { name = libpipewire-module-spa-node-factory }
    { name = libpipewire-module-client-node } { name = libpipewire-module-client-device }
    { name = libpipewire-module-access } { name = libpipewire-module-adapter }
    { name = libpipewire-module-link-factory } { name = libpipewire-module-session-manager }
]
context.objects = [
    { factory = spa-node-factory args = { factory.name = support.node.driver node.name = Dummy-Driver
                                          node.group = pipewire.dummy priority.driver = 20000 } }
]
EOF
cp /usr/share/pipewire/client.conf "$T/pwconf/client.conf"
cp "$H/packaging/privacy/pipewire-private-mic.conf" "$T/pwconf/pipewire.conf.d/60-heimdall-private-mic.conf"
cat > "$T/config/wireplumber/wireplumber.conf.d/10-isolated.conf" <<'EOF'
wireplumber.profiles = { main = {
    hardware.audio = disabled hardware.bluetooth = disabled hardware.video-capture = disabled
    monitor.alsa = disabled monitor.alsa-midi = disabled monitor.bluez = disabled monitor.bluez-midi = disabled
    monitor.v4l2 = disabled monitor.libcamera = disabled support.reserve-device = disabled support.logind = disabled
    support.portal-permissionstore = disabled support.mpris = disabled } }
EOF
cp "$H/packaging/privacy/wireplumber-private-mic.conf" "$T/config/wireplumber/wireplumber.conf.d/60-heimdall-private-mic.conf"
cp "$H/packaging/privacy/private-mic.lua" "$T/data/wireplumber/scripts/heimdall/private-mic.lua"
[ "$OS" = lykanos ] && cp "$H/packaging/privacy/wireplumber-private-mic-lykanos.conf" \
  "$T/config/wireplumber/wireplumber.conf.d/61-heimdall-private-mic-lykanos.conf"
ffmpeg -nostdin -v error -y -f lavfi -i "anoisesrc=d=60:c=pink:a=0.02:r=48000" \
  -f lavfi -i "sine=f=60:d=60:sample_rate=48000" -f lavfi -i "sine=f=120:d=60:sample_rate=48000" \
  -f lavfi -i "sine=f=240:d=60:sample_rate=48000" \
  -filter_complex "[0:a][1:a][2:a][3:a]amix=inputs=4:weights=1 0.08 0.12 0.06:normalize=0[a]" -map "[a]" -ac 1 \
  -c:a pcm_s16le "$T/feed.wav"

export XDG_RUNTIME_DIR=$RUN PIPEWIRE_RUNTIME_DIR=$RUN XDG_CONFIG_HOME=$T/config XDG_STATE_HOME=$T/state \
  XDG_DATA_HOME=$T/data PIPEWIRE_CONFIG_DIR=$T/pwconf LADSPA_PATH=$T/ladspa PIPEWIRE_REMOTE=pipewire-0 \
  DBUS_SESSION_BUS_ADDRESS=unix:path=$RUN/no-bus DBUS_SYSTEM_BUS_ADDRESS=unix:path=$RUN/no-bus
unset WIREPLUMBER_CONFIG_DIR WIREPLUMBER_DATA_DIR

pipewire > "$T/out/pipewire.log" 2>&1 &
PW=$!
sleep 1
[ -S "$RUN/pipewire-0" ] || { echo "the isolated PipeWire did not start"; kill $PW; exit 1; }
WIREPLUMBER_DEBUG=s-heimdall-private-mic:4 wireplumber > "$T/out/wireplumber.log" 2>&1 &
WP=$!
cleanup() { kill $WP $PW 2>/dev/null; wait 2>/dev/null; rm -rf "$RUN"; }
trap cleanup EXIT
sleep 2

# the fake device microphone: a node shaped like a device's (device.api), fed by hand
pw-cli create-node adapter '{ factory.name = support.null-audio-sink node.name = alsa_input.test-mic
  node.description = "Test microphone" media.class = Audio/Source/Virtual device.api = alsa
  audio.position = [ MONO ] object.linger = true priority.session = 2000 }' > /dev/null
sleep 1
dflt() { pw-metadata 0 default.audio.source 2>/dev/null | grep -o '"name":"[^"]*"' | head -1; }
check "the private microphone is the default input" '[ "$(dflt)" = "\"name\":\"heimdall.private-mic\"" ]'
check "status says on" '"$REL/heimdall-private-mic" status --json | grep -q "^{\"enforce\":true,\"node\":true,"'
"$REL/heimdall-private-mic" off
sleep 1
check "off: the device microphone is the default again" '[ "$(dflt)" = "\"name\":\"alsa_input.test-mic\"" ]'
pw-cat -p -P '{ node.autoconnect = false node.name = feeder }' --rate 48000 --channels 1 "$T/feed.wav" &
FEED=$!
sleep 0.5
pw-link feeder:output_MONO alsa_input.test-mic:input_MONO
"$REL/heimdall-private-mic" on
sleep 1
check "on: the private microphone is the default again" '[ "$(dflt)" = "\"name\":\"heimdall.private-mic\"" ]'
pw-record -P '{ node.name = rec-default }' --rate 48000 --channels 1 "$T/out/rec-default.wav" &
R1=$!
pw-record -P '{ node.name = rec-named }' --target alsa_input.test-mic --rate 48000 --channels 1 "$T/out/rec-named.wav" &
R2=$!
sleep 3
links=$(pw-link -l 2>/dev/null)
check "the default recording comes from the private microphone" \
  'echo "$links" | grep -A3 "^rec-default:input_MONO" | grep -q "heimdall.private-mic:capture_MONO"'
check "a recording asking for the device microphone by name gets the private one" \
  'echo "$links" | grep -A3 "^rec-named:input_MONO" | grep -q "heimdall.private-mic:capture_MONO"'
# what a client lists with "ls Node" once connected (pw-cli also prints the globals it is told about while connecting, before
# the permissions are applied: those lines come before its prompt and are not counted)
listed() { ( sleep 2; echo "ls Node"; sleep 1 ) | timeout 5 pw-cli 2>/dev/null | sed -n "/>> ls Node/,\$p" | grep -c 'node.name = "alsa_input.test-mic"'; }
seen=$(listed)
check "a client does not see the device microphone" '[ "$seen" = 0 ]'
check "a client cannot link the device microphone by hand" \
  '! pw-link alsa_input.test-mic:capture_MONO rec-default:input_MONO 2>/dev/null'
# Sarina's voice input. A client cannot see links to the hidden device microphone, so which one a recording heard is told
# by its 120 Hz hum: the device microphone has it (+10 dB and more), the private one has not.
hum_db() { ffmpeg -nostdin -v info -i "$1" -af "bandpass=f=120:width_type=h:w=6,volumedetect" -f null - 2>&1 \
  | sed -n 's/.*mean_volume: \(-*[0-9.]*\) dB/\1/p'; }
louder() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a - b > 10) }'; }
sarina_from() { pw-link -l 2>/dev/null | grep -A3 "^$1:input_MONO" | grep -o -E "(heimdall.private-mic|alsa_input.test-mic):capture_MONO" | head -1; }
sarina() { pw-record -P "{ node.name = $1 heimdall.private-mic.exempt = sarina-voice }" --rate 16000 --channels 1 "$T/out/$1.wav" & }
sarina rec-sarina1; S1=$!
sleep 4
check "Sarina's voice input records the private microphone (the setting is off or absent)" \
  '[ "$(sarina_from rec-sarina1)" = "heimdall.private-mic:capture_MONO" ]'
kill $S1; wait $S1 2>/dev/null
if [ "$OS" = lykanos ]; then
  check "lykanos: the setting exists and is off" \
    'wpctl settings heimdall.private-mic.sarina-raw | grep -q "Value: false"'
  wpctl settings heimdall.private-mic.sarina-raw true > /dev/null
  sleep 1
  sarina rec-sarina2; S2=$!
  sleep 4
  kill $S2; wait $S2 2>/dev/null
  check "lykanos, on: Sarina's voice input records the device microphone (its hum is there)" \
    'louder "$(hum_db "$T/out/rec-sarina2.wav")" "$(hum_db "$T/out/rec-sarina1.wav")"'
  pw-record -P '{ node.name = rec-other }' --target alsa_input.test-mic --rate 16000 --channels 1 "$T/out/rec-other.wav" &
  S3=$!
  sleep 2
  check "lykanos, on: any other recording still gets the private microphone" \
    '[ "$(sarina_from rec-other)" = "heimdall.private-mic:capture_MONO" ]'
  check "lykanos, on: the default recording too" \
    'pw-link -l 2>/dev/null | grep -A3 "^rec-default:input_MONO" | grep -q "heimdall.private-mic:capture_MONO"'
  kill $S3; wait $S3 2>/dev/null
  wpctl settings heimdall.private-mic.sarina-raw false > /dev/null
else
  wpctl settings heimdall.private-mic.sarina-raw true > /dev/null 2>&1
  sleep 1
  sarina rec-sarina2; S2=$!
  sleep 4
  check "labyrinth: even with the setting forced by hand, Sarina's voice input records the private microphone" \
    '[ "$(sarina_from rec-sarina2)" = "heimdall.private-mic:capture_MONO" ]'
  kill $S2; wait $S2 2>/dev/null
  check "labyrinth: and has no hum" '! louder "$(hum_db "$T/out/rec-sarina2.wav")" "$(hum_db "$T/out/rec-sarina1.wav")"'
fi
sleep 30
kill $R1 $R2 $FEED 2>/dev/null
wait $R1 $R2 2>/dev/null
check "the feed has mains hum" '"$REL/heimdall-scrub" --check "$T/feed.wav" | grep -q "grid hum (ENF) present"'
for r in rec-default rec-named; do
  check "$r has sound and no mains hum" \
    '[ $(stat -c %s "$T/out/$r.wav") -gt 3000000 ] && "$REL/heimdall-scrub" --check "$T/out/$r.wav" | grep -q "no grid hum"'
done
"$REL/heimdall-private-mic" off
sleep 1
check "a client sees the device microphone when off" \
  '[ "$(listed)" = 1 ]'
[ $fail = 0 ] && rm -rf "$T" || echo "logs and recordings kept in $T"
exit $fail
