import argparse
from dateutil import parser as datetime_parser
from datetime import timezone, timedelta
import matplotlib.pyplot as plt

parser = argparse.ArgumentParser(description='Take in wazuh log files and plot event flow')
parser.add_argument('--event_file', type=str, default='ossec-events.log', help='input event log file')
parser.add_argument('--alert_file', type=str, default='ossec-alerts.log', help='input alert log file')
parser.add_argument("--event_only", help="only plot events; ignore alerts", action="store_true")
parser.add_argument("--alert_only", help="only plot alerts; ignore events", action="store_true")
parser.add_argument('--hosts', type=str, nargs='+', default=[])

args = parser.parse_args()

def parse_host(line):
  idx_arrow = line.find('->')
  if (idx_arrow  == -1):
    return 'UNKNOWN_HOST'
  idx_left_parenthesis = line.find('(', 21, idx_arrow)
  idx_right_parenthesis = line.find(')', 21, idx_arrow)
  if (idx_left_parenthesis == -1 or idx_right_parenthesis == -1):
    return line[21: idx_arrow]
  return line[idx_left_parenthesis + 1: idx_right_parenthesis]

def match_host(host, hs):
  if (len(hs) == 0):
    return True
  for h in hs:
    if h == host:
      return True
    # if h[-1] == '*' and host.startswith(h[:-1]):
    #   return True
  return False

def utc_to_local(utc_dt):
  return utc_dt.replace(tzinfo=timezone.utc).astimezone(tz=None)

def round_dt(dt):
  dt_round = dt - timedelta(minutes=dt.minute % 10, seconds=dt.second, microseconds=dt.microsecond)
  return dt_round

def parse_log(filepath):
  time_spans = []
  log_counts = {}
  log_file = open(filepath, 'r', encoding='utf-8', errors='ignore')

  while True:
    line = log_file.readline()
    try:
      time = round_dt(datetime_parser.parse(line[:20]))
      host = parse_host(line)
      if (not match_host(host, args.hosts)):
        continue
      if (len(time_spans) == 0):
        time_spans.append(time.strftime("%H:%M"))
        log_counts[host] = [0]
      if (host not in log_counts):
        log_counts[host] = [0] * len(log_counts[list(log_counts.keys())[0]])
      if (time.strftime("%H:%M") != time_spans[-1]):
        time_spans.append(time.strftime("%H:%M"))
        for h in log_counts:
          log_counts[h].append(0)
      log_counts[host][-1] += 1
    except datetime_parser.ParserError:
      pass
    if not line:
      break

  log_file.close()
  return time_spans, log_counts

event_time_spans, event_log_counts = [], {}
if (not args.alert_only):
  print('Parsing event log...')
  event_time_spans, event_log_counts = parse_log(args.event_file)

alert_time_spans, alert_log_counts = [], {}
if (not args.event_only):
  print('Parsing alert log...')
  alert_time_spans, alert_log_counts = parse_log(args.alert_file)

for host in event_log_counts:
  plt.plot(event_time_spans, event_log_counts[host], label = f"Event - {host}")
  print(f"Total logs of [Event - {host}]: {sum(event_log_counts[host])}")
for host in alert_log_counts:
  plt.plot(alert_time_spans, alert_log_counts[host], label = f"Alert - {host}")
  print(f"Total logs of [Alert - {host}]: {sum(alert_log_counts[host])}")
plt.title("Log Counts within One Day")
plt.ylabel("Count")
plt.xlabel("Time")
plt.xticks(rotation=90, fontsize=6)

ax = plt.gca()
labels = ax.xaxis.get_ticklabels()
labels = list(set(labels) - set(labels[::6]))
for label in labels:
  label.set_visible(False)

plt.legend()
plt.show()