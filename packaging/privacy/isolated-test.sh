#!/bin/bash
# packaging/privacy/isolated-test.sh TARGET_DIR: the private microphone end to end, in a PipeWire and WirePlumber of its
# own, never the desktop's: own runtime, config, state and data folders, no D-Bus, no ALSA/Bluetooth/camera monitors.
# A fake device microphone is fed synthetic room noise with 60 Hz mains hum; two recordings (the default input, and one
# that asks for the device microphone by name) must both come from the private microphone, the device microphone must be
# invisible to clients and refuse a manual link, and the recordings must have no mains hum (ENF) left.
#
# TARGET_DIR holds release builds of heimdall-scrub, heimdall-private-mic and libheimdall_scrub_ladspa.so
# (cd rust && cargo build --release -p heimdall-scrub -p heimdall-scrub-ladspa). Needs pipewire, wireplumber, ffmpeg.
# Takes about a minute. Exit 0 = every check passed.
set -u
REL=$(realpath "${1:?usage: isolated-test.sh TARGET_DIR}")
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
check "status says on" '[ "$("$REL/heimdall-private-mic" status --json)" = "{\"enforce\":true,\"node\":true}" ]'
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
seen=$( (sleep 1; echo "ls Node"; sleep 1) | timeout 4 pw-cli 2>/dev/null | grep -c 'node.name = "alsa_input.test-mic"')
check "a client does not see the device microphone" '[ "$seen" = 0 ]'
check "a client cannot link the device microphone by hand" \
  '! pw-link alsa_input.test-mic:capture_MONO rec-default:input_MONO 2>/dev/null'
sleep 40
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
  '[ "$( (sleep 1; echo "ls Node"; sleep 1) | timeout 4 pw-cli 2>/dev/null | grep -c "node.name = \"alsa_input.test-mic\"")" = 1 ]'
[ $fail = 0 ] && rm -rf "$T" || echo "logs and recordings kept in $T"
exit $fail
