# Synthetic fixture: a "helper" that schedules itself. Modelled on the cron
# foothold shape in Datadog's malicious PyPI samples. Pure file writes so the
# only CodePatterns findings come from the persistence rules.
import os

JOB = "* * * * * python3 /tmp/.cache/agent_helper.py\n"

with open("/etc/cron.d/agent_helper", "w") as f:
    f.write(JOB)
