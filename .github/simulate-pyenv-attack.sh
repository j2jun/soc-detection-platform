# Runs on the CI runner (a throwaway VM). Records auditd telemetry for two phases:
#   legit.log  - real pyenv building its own shims (must NOT alert)
#   attack.log - "malware" overwriting a shim, like the Binance take-home assignment (must alert)
# The payload is inert: it only echoes.
set -euo pipefail
export PYENV_ROOT="$HOME/.pyenv" PATH="$HOME/.pyenv/bin:$PATH"
LOG=/var/log/audit/audit.log

mkdir -p "$PYENV_ROOT/shims" "$PYENV_ROOT/versions/3.12.0/bin"
printf '#!/bin/sh\n' > "$PYENV_ROOT/versions/3.12.0/bin/python"
chmod +x "$PYENV_ROOT/versions/3.12.0/bin/python"
sudo auditctl -w "$PYENV_ROOT/shims" -p wa -k pyenv_shim

pyenv rehash                        # benign: pyenv writes shims/python itself
sleep 2
sudo cat "$LOG" > legit.log
n=$(wc -l < legit.log)

python3 -c "open('$PYENV_ROOT/shims/python', 'w').write('#!/bin/sh\necho pwned\n')"
sleep 2
sudo tail -n "+$((n + 1))" "$LOG" > attack.log
echo "legit.log: $(grep -c pyenv_shim legit.log) shim events, attack.log: $(grep -c pyenv_shim attack.log)"
