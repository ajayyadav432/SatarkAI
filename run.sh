#!/usr/bin/env bash
# SatarkAI - one command to run, test or retrain.
#   ./run.sh          start the app on http://localhost:8000
#   ./run.sh test     run all tests
#   ./run.sh train    download the datasets and retrain the models
#   ./run.sh seed     add demo cases so the dashboard is not empty
#   ./run.sh unseed   remove the demo cases again
#   ./run.sh demo     serve the demo web pages (fake social network) on port 8765
#   ./run.sh phone    keep the phone connected over USB (re-applies adb reverse)
set -euo pipefail
cd "$(dirname "$0")"

# (Re)create the environment when it is missing or was made by a different Python,
# for example after copying the folder to another computer.
if ! .venv/bin/python -c "import fastapi, sklearn, tldextract, uvicorn" 2>/dev/null; then
  echo "Creating the Python environment (first run only, needs internet)..."
  rm -rf .venv
  python3 -m venv .venv
  .venv/bin/python -m pip install --quiet --disable-pip-version-check -r requirements.txt
fi
PY=.venv/bin/python
HOST="${SATARK_HOST:-127.0.0.1}"
PORT="${SATARK_PORT:-8000}"

case "${1:-serve}" in
  serve)
    if [ ! -f models/text_model.joblib ] || [ ! -f models/url_model.joblib ]; then
      echo "Note: models are missing. Rules and link checks still work. Run './run.sh train' to add the models."
    fi
    echo "SatarkAI is starting on http://${HOST}:${PORT}  (Ctrl+C to stop)"
    exec "$PY" -m uvicorn app.main:app --host "$HOST" --port "$PORT"
    ;;
  test)
    shift
    exec "$PY" -m pytest "$@"
    ;;
  train)
    "$PY" -m ml.download_data
    exec "$PY" -m ml.train
    ;;
  seed)
    exec "$PY" scripts/seed_demo.py
    ;;
  phone)
    # Keeps the USB link to the phone alive: the phone's 127.0.0.1:8000 reaches this laptop.
    # Android drops this link whenever the cable is re-plugged, so it is re-applied every 5 seconds.
    ADB="$(command -v adb || echo "$HOME/Android/Sdk/platform-tools/adb")"
    RUN=""
    [ -f /.flatpak-info ] && RUN="flatpak-spawn --host"     # VS Code Flatpak: adb lives on the host
    echo "Keeping the phone connected over USB (Ctrl+C to stop). In the app use http://127.0.0.1:8000"
    while true; do
      for d in $($RUN "$ADB" devices | awk 'NR>1 && $2=="device" && $1 !~ /^emulator-/ {print $1}'); do
        $RUN "$ADB" -s "$d" reverse --list 2>/dev/null | grep -q "tcp:8000" ||
          { $RUN "$ADB" -s "$d" reverse tcp:8000 tcp:8000 >/dev/null 2>&1 && echo "$(date +%H:%M:%S) phone $d connected"; }
      done
      sleep 5
    done
    ;;
  demo)
    echo "Demo pages with fake scam links on http://127.0.0.1:8765  (Ctrl+C to stop)"
    exec "$PY" -m http.server 8765 --bind 127.0.0.1 --directory demo
    ;;
  unseed)
    exec "$PY" scripts/seed_demo.py --remove
    ;;
  *)
    echo "Usage: ./run.sh [serve|test|train|seed|unseed|demo|phone]"
    exit 2
    ;;
esac
