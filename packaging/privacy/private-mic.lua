-- Heimdall: the private microphone (WirePlumber 0.5 script).
--
-- PipeWire's filter-chain makes "Microphone (private)" (node heimdall.private-mic): the real microphone, scrubbed of the
-- sounds that can place or date a recording (heimdall-scrub's live mode, a LADSPA plugin). While the setting
-- heimdall.private-mic.enforce is on (the default), this script makes every app record that node:
--
-- 1. default: the private microphone is the default input (the choice the owner made is kept as the configured
--    default and comes back when enforcement is off);
-- 2. linking: any recording stream WirePlumber would link to a physical microphone (an app that picks a device by
--    name, a remembered per-app choice, an ALSA or JACK app going through PipeWire) is linked to the private one;
-- 3. hiding: ordinary clients cannot see physical microphones at all, so device lists offer only the private one
--    and nothing can link to them by hand (pw-link, JACK). pipewire-pulse is one such client, so every PulseAudio app
--    (browsers, Teams, Zoom, Discord, OBS) sees only the private microphone.
--
-- The filter's own input is linked to the physical microphone the owner chose (default.configured.audio.source), or the
-- best one. Turn it off with `heimdall-private-mic off` (Settings > Security > Privacy): everything goes back to normal at
-- once, no restart. What it cannot stop: a program that opens the sound card directly (ALSA hw: while PipeWire is not
-- using it), a portal client's own manual links, recordings on other devices. docs/LOCATION_SOUNDS.md.

cutils = require ("common-utils")
lutils = require ("linking-utils")
log = Log.open_topic ("s-heimdall-private-mic")

PRIVATE = "heimdall.private-mic"
CAPTURE = "heimdall.private-mic.capture"
KEY = "heimdall.private-mic.enforce"

function enforcing ()
  local v = Settings.get_boolean (KEY)
  if v == nil then
    return true
  end
  return v
end

-- A microphone of a device (ALSA, Bluetooth, a webcam), not a virtual source or a filter.
function isPhysicalSource (props)
  if props == nil then
    return false
  end
  local mc = props ["media.class"]
  if mc ~= "Audio/Source" and mc ~= "Audio/Duplex" and mc ~= "Audio/Source/Virtual" then
    return false
  end
  if props ["node.link-group"] ~= nil or props ["node.name"] == PRIVATE then
    return false
  end
  return props ["device.api"] ~= nil or props ["device.id"] ~= nil
end

function nodeProps (si)
  local n = si and si:get_associated_proxy ("node")
  return n and n.properties
end

function configuredSource (source)
  local om = source:call ("get-object-manager", "metadata")
  local m = om and om:lookup { Constraint { "metadata.name", "=", "default" } }
  local v = m and m:find (0, "default.configured.audio.source")
  if v == nil then
    return nil
  end
  local ok, parsed = pcall (function () return Json.Raw (v):parse () end)
  return ok and type (parsed) == "table" and parsed.name or nil
end

-- The physical microphone the private one listens to.
function bestPhysical (source, om, si_props)
  local want = configuredSource (source)
  local best, best_prio = nil, nil
  for si in om:iterate { type = "SiLinkable" } do
    local p = nodeProps (si)
    if isPhysicalSource (p) and lutils.canLink (si_props, si) then
      if want ~= nil and p ["node.name"] == want then
        return si
      end
      local prio = tonumber (p ["priority.session"]) or 0
      if best == nil or prio > best_prio then
        best, best_prio = si, prio
      end
    end
  end
  return best
end

SimpleEventHook {
  name = "heimdall/private-mic-target",
  after = { "linking/find-defined-target", "linking/find-filter-target", "linking/find-media-role-target",
            "linking/find-default-target", "linking/find-best-target", "linking/get-filter-from-target" },
  before = "linking/prepare-link",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "select-target" },
    },
  },
  execute = function (event)
    if not enforcing () then
      return
    end
    local source, om, si, si_props, si_flags, target = lutils:unwrap_select_target_event (event)
    if si_props ["media.class"] ~= "Stream/Input/Audio" or cutils.parseBool (si_props ["stream.capture.sink"]) then
      return
    end
    local own = nodeProps (si)
    if own ~= nil and own ["node.name"] == CAPTURE then
      -- the filter's input: a physical microphone, never itself
      if target == nil or not isPhysicalSource (nodeProps (target)) then
        local t = bestPhysical (source, om, si_props)
        if t ~= nil then
          log:info (si, "private microphone listens to " .. tostring (nodeProps (t) ["node.name"]))
          event:set_data ("target", t)
        end
      end
      return
    end
    if target ~= nil and not isPhysicalSource (nodeProps (target)) then
      return
    end
    local private = om:lookup { type = "SiLinkable", Constraint { "node.name", "=", PRIVATE } }
    if private ~= nil and lutils.canLink (si_props, private) then
      log:info (si, "recording goes to the private microphone instead of " ..
          tostring (target and nodeProps (target) ["node.name"]))
      event:set_data ("target", private)
    end
  end
}:register ()

SimpleEventHook {
  name = "heimdall/private-mic-default",
  after = { "default-nodes/find-best-default-node", "default-nodes/find-selected-default-node",
            "default-nodes/find-stored-default-node" },
  before = "default-nodes/apply-default-node",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "select-default-node" },
    },
  },
  execute = function (event)
    if not enforcing () or event:get_properties () ["default-node.type"] ~= "audio.source" then
      return
    end
    local available = event:get_data ("available-nodes")
    available = available and available:parse ()
    for _, p in ipairs (available or {}) do
      if p ["node.name"] == PRIVATE then
        event:set_data ("selected-node", PRIVATE)
        return
      end
    end
  end
}:register ()

-- Physical microphones are invisible to ordinary clients while enforcement is on.
function hidePhysical (_, client, node)
  if enforcing () and isPhysicalSource (node.properties) then
    log:info (client, "hiding " .. tostring (node.properties ["node.name"]) .. " from " ..
        tostring (client:get_property ("application.name")))
    return Perm.NONE
  end
  return nil
end

physicalMics = Interest {
  type = "node",
  Constraint { "media.class", "c", "Audio/Source", "Audio/Duplex", "Audio/Source/Virtual" },
}

private_pm = PermissionManager ()
private_pm:set_default_permissions (Perm.ALL)
private_pm:add_interest_match (function (pm, c, n) return hidePhysical (pm, c, n) or Perm.ALL end, physicalMics)

private_restricted_pm = PermissionManager ()
private_restricted_pm:set_default_permissions (Perm.RX)
private_restricted_pm:add_interest_match (function (pm, c, n) return hidePhysical (pm, c, n) or Perm.RX end, physicalMics)

SimpleEventHook {
  name = "heimdall/private-mic-access",
  after = { "client/find-config-access", "client/find-flatpak-access", "client/find-snap-access",
            "client/find-portal-access" },
  before = "client/find-default-access",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "select-access" },
    },
  },
  execute = function (event)
    -- a client another rule already gave a permission manager (config, Flatpak, Snap, portal) keeps it
    if event:get_data ("permission-manager") ~= nil or event:get_data ("default-permissions") ~= nil then
      return
    end
    local client = event:get_subject ()
    local access = cutils.get_client_access (client.properties)
    event:set_data ("permission-manager", access == "restricted" and private_restricted_pm or private_pm)
  end
}:register ()

for name, pm in pairs ({ ["private"] = private_pm, ["private-restricted"] = private_restricted_pm }) do
  pm:activate (Features.ALL, function (_, e)
    if e then
      log:warning ("failed to activate the " .. name .. " permission manager: " .. tostring (e))
    end
  end)
end

Settings.subscribe (KEY, function ()
  log:notice ("private microphone enforcement " .. (enforcing () and "on" or "off"))
  private_pm:update_permissions ()
  private_restricted_pm:update_permissions ()
  local source = Plugin.find ("standard-event-source")
  if source ~= nil then
    source:call ("schedule-rescan", "default-nodes")
    source:call ("schedule-rescan", "linking")
  end
end)
