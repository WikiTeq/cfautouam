#!/bin/bash
# Cloudflare Auto Under Attack Mode = CF Auto UAM
# version 1.0
#
# Hardened rewrite:
#   - CPU load samples are validated as non-negative integers; bad samples skip the cycle
#     instead of being read as near-zero load (prevents spurious UAM disables).
#   - All Cloudflare API calls send timeouts, check curl exit status, and parse the JSON
#     "success" flag; failures are logged and never recorded as success.
#   - HTTP 429 responses trigger a bounded exponential backoff before giving up.
#   - UAM enable/disable decisions no longer require the zone level to equal a single
#     configured string; any non-UAM level can be escalated, any UAM level reverted.
#   - State files are checked before reading; missing state is treated as unknown.
#   - Authentication uses a scoped Cloudflare API token (Authorization: Bearer) instead of
#     the deprecated Global API Key headers.

# Security Level Enums
SL_OFF=0
SL_ESSENTIALLY_OFF=1
SL_LOW=2
SL_MEDIUM=3
SL_HIGH=4
SL_UNDER_ATTACK=5

# Security Level Strings
SL_OFF_S="off"
SL_ESSENTIALLY_OFF_S="essentially_off"
SL_LOW_S="low"
SL_MEDIUM_S="medium"
SL_HIGH_S="high"
SL_UNDER_ATTACK_S="under_attack"

#config
debug_mode=0 # 1 = true, 0 = false, adds more logging & lets you edit vars to test the script
install_parent_path="/home"
cf_api_token=""          # scoped Cloudflare API token (Zone > Zone Settings > Edit for your zone)
cf_zoneid=""
upper_cpu_limit=35       # enable UAM above this CPU load percentage
lower_cpu_limit=5        # disable UAM below this CPU load percentage
regular_status_s=$SL_HIGH_S
time_limit_before_revert=$((60 * 5)) # 5 minutes by default
curl_connect_timeout=10
curl_max_time=30
max_429_retries=3        # bounded exponential backoff on HTTP 429
#end config

log() {
  echo "$(date) - cfautouam - $*" >>"$install_parent_path/cfautouam/cfautouam.log"
}

debug_log() {
  if [ "$debug_mode" = 1 ]; then
    log "$*"
  fi
}

is_nonneg_int() {
  [[ $1 =~ ^[0-9]+$ ]]
}

cf_request() {
  # cf_request METHOD PATH [JSON_BODY]
  local method=$1 path=$2 body=${3:-}
  local args=(-sS -X "$method"
    -H "Authorization: Bearer $cf_api_token"
    -H "Content-Type: application/json"
    --connect-timeout "$curl_connect_timeout"
    --max-time "$curl_max_time"
    -w '\n%{http_code}'
    "https://api.cloudflare.com/client/v4$path")
  [ -n "$body" ] && args+=(--data "$body")

  curl "${args[@]}" 2>/dev/null
}

cf_request_with_backoff() {
  # Retries on curl transport failure and HTTP 429 with exponential backoff.
  local method=$1 path=$2 body=${3:-}
  local attempt response http_code success rc

  for attempt in $(seq 0 "$max_429_retries"); do
    response=$(cf_request "$method" "$path" "$body")
    rc=$?
    http_code=$(printf '%s\n' "$response" | tail -n 1)

    if ! is_nonneg_int "$http_code"; then
      log "API request failed: no HTTP status from curl (transport error)"
      return 1
    fi

    case $http_code in
      429)
        if [ "$attempt" -lt "$max_429_retries" ]; then
          local wait_seconds=$((2 ** attempt))
          log "HTTP 429 rate limited, retrying in ${wait_seconds}s"
          sleep "$wait_seconds"
          continue
        fi
        log "API request rate limited after $((max_429_retries + 1)) attempts"
        return 1
        ;;
      2*) ;;
      *)
        log "API request failed with HTTP $http_code: $(printf '%s' "$response" | head -n 1 | cut -c1-300)"
        return 1
        ;;
    esac

    success=$(printf '%s\n' "$response" | head -n 1 | grep -o '"success": *true' || true)
    if [ -z "$success" ]; then
      log "API returned HTTP $http_code but success flag not true: $(printf '%s' "$response" | head -n 1 | cut -c1-300)"
      return 1
    fi
    printf '%s\n' "$response" | head -n 1
    return 0
  done
}

install() {
  mkdir -p "$install_parent_path/cfautouam"

  cat >"$install_parent_path/cfautouam/cfautouam.service" <<EOF
[Unit]
Description=Automate Cloudflare Under Attack Mode
[Service]
ExecStart=$install_parent_path/cfautouam/cfautouam.sh
EOF

  cat >"$install_parent_path/cfautouam/cfautouam.timer" <<EOF
[Unit]
Description=Automate Cloudflare Under Attack Mode
[Timer]
OnBootSec=60
OnUnitActiveSec=5
AccuracySec=1
[Install]
WantedBy=timers.target
EOF

  systemctl enable "$install_parent_path/cfautouam/cfautouam.timer"
  systemctl enable "$install_parent_path/cfautouam/cfautouam.service"
  systemctl start cfautouam.timer
  log "Installed"
  exit
}

uninstall() {
  systemctl stop cfautouam.timer
  systemctl stop cfautouam.service
  systemctl disable cfautouam.timer
  systemctl disable cfautouam.service
  rm -f "$install_parent_path/cfautouam/cfstatus"
  rm -f "$install_parent_path/cfautouam/uamdisabledtime"
  rm -f "$install_parent_path/cfautouam/uamenabledtime"
  rm -f "$install_parent_path/cfautouam/cfautouam.timer"
  rm -f "$install_parent_path/cfautouam/cfautouam.service"
  log "Uninstalled"
  exit
}

disable_uam() {
  if cf_request_with_backoff PATCH "/zones/$cf_zoneid/settings/security_level" \
    "{\"value\":\"$regular_status_s\"}" >/dev/null; then
    date +%s >"$install_parent_path/cfautouam/uamdisabledtime"
    log "CPU Load: $curr_load - Disabled UAM"
  else
    log "CPU Load: $curr_load - FAILED to disable UAM (zone left as-is)"
  fi
}

enable_uam() {
  if cf_request_with_backoff PATCH "/zones/$cf_zoneid/settings/security_level" \
    '{"value":"under_attack"}' >/dev/null; then
    date +%s >"$install_parent_path/cfautouam/uamenabledtime"
    log "CPU Load: $curr_load - Enabled UAM"
  else
    log "CPU Load: $curr_load - FAILED to enable UAM (zone left as-is)"
  fi
}

get_current_load() {
  curr_load=""
  local top_out raw_load
  top_out=$(top -bn1)
  raw_load=$(printf '%s\n' "$top_out" | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
  raw_load=$(echo "$raw_load/1" | bc 2>/dev/null)
  if is_nonneg_int "$raw_load"; then
    curr_load=$raw_load
    return 0
  fi
  echo "$(date) - cfautouam - could not parse CPU load sample (raw='$(printf '%s\n' "$top_out" | grep 'Cpu(s)' || echo EMPTY)')" >&2
  return 1
}

get_security_level() {
  local response value
  response=$(cf_request_with_backoff GET "/zones/$cf_zoneid/settings/security_level") || {
    security_level="UNKNOWN"
    return 100
  }
  value=$(printf '%s' "$response" | grep -o '"value": *"[^"]*"' | head -n 1 | cut -d'"' -f4)
  case $value in
  "off") return $SL_OFF ;;
  "essentially_off") return $SL_ESSENTIALLY_OFF ;;
  "low") return $SL_LOW ;;
  "medium") return $SL_MEDIUM ;;
  "high") return $SL_HIGH ;;
  "under_attack") return $SL_UNDER_ATTACK ;;
  *)
    security_level="UNKNOWN"
    return 100
    ;;
  esac
}

main() {
  get_security_level
  curr_security_level=$?

  if [ "$curr_security_level" = 100 ]; then
    log "could not determine current security level (level=UNKNOWN), skipping this cycle"
    exit
  fi

  if ! get_current_load; then
    log "CPU load sample unavailable this cycle, skipping toggles to avoid false readings"
    exit
  fi

  debug_log "state: level=$curr_security_level load=$curr_load"

  # If the zone is in Under Attack mode
  if [ "$curr_security_level" = "$SL_UNDER_ATTACK" ]; then
    if [ ! -r "$install_parent_path/cfautouam/uamenabledtime" ]; then
      log "UAM is active but uamenabledtime is missing/unreadable, skipping revert decision this cycle"
      exit
    fi
    uam_enabled_time=$(<"$install_parent_path/cfautouam/uamenabledtime")
    if ! is_nonneg_int "$uam_enabled_time"; then
      log "uamenabledtime contains garbage ('$(cat "$install_parent_path/cfautouam/uamenabledtime")'), skipping revert decision this cycle"
      exit
    fi
    currenttime=$(date +%s)
    timediff=$((currenttime - uam_enabled_time))

    if [ "$timediff" -lt "$time_limit_before_revert" ]; then
      debug_log "CPU Load: $curr_load - time limit has not passed regardless of CPU - do nothing"
      exit
    fi

    if [ "$curr_load" -lt "$lower_cpu_limit" ]; then
      debug_log "CPU Load: $curr_load - time limit passed - CPU below threshold"
      disable_uam
    else
      debug_log "CPU Load: $curr_load - time limit passed but CPU above threshold, waiting out time limit"
    fi
    exit
  fi

  # Zone is not in Under Attack mode: escalate under sustained high load regardless of
  # which specific non-UAM level the zone currently sits at.
  if [ "$curr_load" -gt "$upper_cpu_limit" ]; then
    enable_uam
  else
    debug_log "CPU Load: $curr_load - no change necessary"
  fi
}

# End Functions

# Main -> command line arguments

if [ "$1" = '-install' ]; then
  install
elif [ "$1" = '-uninstall' ]; then
  uninstall
elif [ "$1" = '-enable_uam' ]; then
  mkdir -p "$install_parent_path/cfautouam"
  curr_load="manual"
  log "UAM Manually Enabled"
  enable_uam
  exit
elif [ "$1" = '-disable_uam' ]; then
  mkdir -p "$install_parent_path/cfautouam"
  curr_load="manual"
  log "UAM Manually Disabled"
  disable_uam
  exit
elif [ -z "$1" ]; then
  main
  exit
else
  echo "cfautouam - Invalid argument"
  exit
fi
