'''
Load files

'''

import sys, re

# Define colors - yay color!
# Need more - build out later
class colors:
	HEADER = '\033[95m'
	BLUE = '\033[94m'
	GREEN = '\033[92m'
	SECTION = '\033[93m'
	RED = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	WHITE = '\033[1;37m'
	GREY = '\033[37m'
	HEADER_BOLD = '\033[95m' + '\033[1m'
	WARN = '\033[33m'
	PURPLE = '\033[35m'
	CYAN = '\033[36m'
	DBLUE = '\033[34m'
	
ha_logs = []

for arg in sys.argv[1:]:
	ha_logs.append(arg)
	
if len(ha_logs) < 2:
	print colors.WARN + "Less than 2 files specififed, try again" + colors.ENDC
	sys.exit()
	
print colors.HEADER + "Comparing the following files:" + colors.ENDC
for logname in ha_logs:
	print colors.BLUE + "File: " + logname + colors.ENDC
	
print ""

FILE_LIST = []
def load_logs(logs):
	for l in logs:
		#print colors.GREEN +"DEBUG: " + colors.ENDC +"Loading files " + l
		try:
			temp_file = open(l, 'r')
			FILE_LIST.append(temp_file)
		except IOError as err:
			print colors.WARN +"Could not load file " + l +", exiting..."+colors.ENDC
			sys.exit()
			
LOG1_LINES = []
LOG2_LINES = []
def grab_host_stats(logs):
	'''
	This is meant to pull all the _collect_all_host_stats() log lines for parsing
	'''
	log1 = logs[0]
	log2 = logs[1]
	print colors.BLUE + "Pulling _collect_all_hosts_stats lines from first log" + colors.ENDC
	
	count = 0
	for line in log1.readlines():
		if '_collect_all_host_stats' in line:
			LOG1_LINES.append(line)
			count += 1
			
	print colors.BLUE + "Found " + str(count) + " lines in the first log" + colors.ENDC		
	
	print colors.BLUE + "Pulling _collect_all_hosts_stats lines from second log" + colors.ENDC

	
	count = 0
	for line in log2.readlines():
		if '_collect_all_host_stats' in line:
			LOG2_LINES.append(line)
			count += 1
			
	print colors.BLUE + "Found " + str(count) + " lines in the second log" + colors.ENDC
	
HOSTNAMES = []		
def find_hostnames(lines):
	p = re.compile('\{.*\}')
	for line in lines:
		if 'collect_all_host_stat' in line and not 'Global' in line:
			if len(p.findall(line)) > 0:
				l = eval(p.findall(line)[0])
				hn = l['hostname']
				if not hn in HOSTNAMES:
					HOSTNAMES.append(hn)
					print "Adding host " + hn + " to list"
	print "Hosts found: " + str(HOSTNAMES)
	
def parse_host_stats(loglines, hostname):
	'''
	Take in hostname
	Run through all lines
		if line matches all criteria including the host name
			parse the dict embedded in the line
	'''
	host_history = []
	history_item = {}
	p = re.compile('\{.*\}')
	ts = re.compile('\d{2}:\d{2}:\d{2}')
	
	for line in loglines:
		if 'collect_all_host_stat' in line and not 'Global' in line:
			if len(p.findall(line)) > 0:
				l = eval(p.findall(line)[0])
				time = ts.findall(line)[0]
				history_item['ts'] = str(time)
				history_item['health'] = l['engine-status']['health']
				history_item['score'] = l['score']
				if 'up' in l['engine-status']['vm']:
					history_item['runningVM'] = True
				else:
					history_item['runningVM'] = False
				#print history_item
				host_history.append(history_item)
	print "Found " + str(len(host_history)) + " history items for host "+hostname
	return host_history
	
	
def print_table_header(host1, host2):
	print colors.HEADER_BOLD+"{:9}\t{:^19} | {:^19}".format("",host1,host2)+colors.ENDC
	
	print colors.HEADER + "{:9}\t{:6}\t{:3}\t{:3} | {:3}\t{:5}\t{:5}".format("Timestamp","Health","Score","VM?","VM?","Score","Health")+colors.ENDC
	
def print_table_row(timestamp, health1, score1, vm1, vm2, score2, health2):
	print colors.HEADER + "{:12}\t{:^6}\t{:^3}\t{:^3} | {:^3}\t{:^5}\t{:^5}".format(timestamp,health1,score1,vm1,vm2,score2,health2)+colors.ENDC
	
	
load_logs(ha_logs)

grab_host_stats(FILE_LIST)

print colors.BLUE + "Finding hostnames..." + colors.ENDC
find_hostnames(LOG1_LINES)

print colors.BLUE + "Finding host history in logs..."+colors.ENDC

host1_hist = parse_host_stats(LOG1_LINES, HOSTNAMES[0])
#print host1_hist


host2_hist = parse_host_stats(LOG1_LINES, HOSTNAMES[1])
			
print_table_header(HOSTNAMES[0], HOSTNAMES[1])

lower = 0
if len(host1_hist) < len(host2_hist):
	lower = len(host1_hist)
elif len(host2_hist) < len(host1_hist):
	lower = len(host2_hist)
else:
	lower = len(host1_hist)   # doesn't matter which length is used, it's the same
	
print colors.DBLUE + "Using " + str(lower) + " as the smaller of the two lengths"

for x in range(0,lower):
	#print colors.DBLUE + "x = " + str(x)
	timestamp1 = host1_hist[x]['ts']
	timestamp2 = host2_hist[x]['ts']
	#print colors.DBLUE + "Checking timestamps on the " + str(x) +"th run."
	if timestamp1 == timestamp2:
		#print colors.DBLUE + "Found matching timestamps"
		line_ts = timestamp1   # doesn't matter, same value
		health1 = host1_hist[x]['health']
		score1 = host1_hist[x]['score']
		if host1_hist[x]['runningVM']:
			vm1 = 'X'
		else:
			vm1 = '-'
		if host2_hist[x]['runningVM']:
			vm2 = 'X'
		else:
			vm2 = '-'
		score2 = host2_hist[x]['score']
		health2 = host2_hist[x]['health']
		print_table_row(line_ts,health1,score1,vm1,vm2,score2,health2)
	else:
		break
	