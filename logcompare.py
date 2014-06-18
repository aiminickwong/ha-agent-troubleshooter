#!/usr/bin/env python

import sys, re, datetime, time

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
	print colors.WARN + "Less than 2 files specififed!" + colors.ENDC
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
	p = re.compile('\{.*\}')
	ts = re.compile('\d{2}:\d{2}:\d{2}')
	
	for line in loglines:
		history_item = {}
		if 'collect_all_host_stat' in line and not 'Global' in line:
			if len(p.findall(line)) > 0:
				l = eval(p.findall(line)[0])
				time = ts.findall(line)[0]
				history_item['ts'] = str(time)
				#print "Set time for hist_item to " + str(time)
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
	
	
def find_score_penalties(hostname, logfile):
	'''
	In hosted_engine.py the _generate_local_blocks() method is used to calculate HA score
	This method will attempt to find any changes in score by looking for that ^^ method name in the log file and parsing the line
	'''
	score_log = []
	
	print "\n"+colors.HEADER_BOLD + "HA Score analysis for host " + hostname
	print "===============================================" + colors.ENDC
	
	# open the passed file
	try:
		openfile = open(logfile, 'r')
	except:
		print "Error loading file, exiting.."
		sys.exit()
		
	line_count = 0
	for line in openfile.readlines():

		if 'generate_local_block' in line:
			#print "Found line"
			line_count += 1
			scoreinfo = {}
			
			# set up regex for parsing lines
			score_report = re.compile(ur'Score is\s(\d*).*to')
			score_report_reason = re.compile(ur'to\s(.*)\sat')
			penalty_score = re.compile(ur'by\s(\d.*)\sdue')
			penalty_score_reason = re.compile(ur'due\sto\s(.*)\sat')
			ts_regex = re.compile(ur'at\s(.*)\n')
			ts_format = '%a %b  %d %H:%M:%S %Y'
			
			# reformat the timestamp to add zero padding to day of the month
			if len(ts_regex.findall(line)) != 0:
				padded_ts = re.sub(r'(\w{3})\s\s(\d{1})',r'\1 0\2', ts_regex.findall(line)[0])
				# make the datetime object (for ease of comparison)
				timestamp = datetime.datetime.strptime(padded_ts, ts_format)
			else:
				timestamp = 'ERR'
			
			
			# Check to see if this is reporting a score
			if len(score_report.findall(line)) != 0:
				# SAMPLE: Score is 0 due to bad engine health at Thu Apr  3 08:01:59 2014
				scoreinfo['score'] = str(score_report.findall(line)[0])
				if len(score_report_reason.findall(line)) != 0:
					scoreinfo['reason'] = "REPORT: " + score_report_reason.findall(line)[0]
					scoreinfo['timestamp'] = timestamp
					score_log.append(scoreinfo)
			# Check to see if we're penalizing a score
			elif len(penalty_score.findall(line)) != 0:
				# SAMPLE: Penalizing score by 400 due to low free memory
				scoreinfo['score'] = str(penalty_score.findall(line)[0])
				if len(penalty_score_reason.findall(line)) != 0:
					scoreinfo['reason'] = "PENALTY: " + penalty_score_reason.findall(line)[0]
					scoreinfo['timestamp'] = timestamp
					score_log.append(scoreinfo)
			else:
				print "Problematic line: " + line
				
	for x in range(0,len(score_log)-1):
		pscore = score_log[x]['score']
		preason = score_log[x]['reason']
		ptimestamp = score_log[x]['timestamp']
		
		print str(ptimestamp) +": "+ preason + " - Score: " + pscore
	

				
			
			
	
load_logs(ha_logs)

grab_host_stats(FILE_LIST)

print colors.BLUE + "Finding hostnames..." + colors.ENDC
find_hostnames(LOG1_LINES)

print colors.BLUE + "Finding host history in logs..."+colors.ENDC

host1_hist = parse_host_stats(LOG1_LINES, HOSTNAMES[0])
#print host1_hist

host2_hist = parse_host_stats(LOG1_LINES, HOSTNAMES[1])
#print host2_hist

print ""			
print_table_header(HOSTNAMES[0], HOSTNAMES[1])

'''
Below we check to see if one host has fewer log lines than the other.
TODO: If one file is bigger, add loop for the difference.
'''
lower = 0
print "Comparing length of host1_hist ("+str(len(host1_hist))+") to length of host2_hist ("+str(len(host2_hist))+")"
if len(host1_hist) < len(host2_hist):
	lower = len(host1_hist)
elif len(host2_hist) < len(host1_hist):
	lower = len(host2_hist)
else:
	lower = len(host1_hist)   # doesn't matter which length is used, it's the same
	
#print "Using " + str(lower) + " as the smaller of the two lengths"

for x in range(0,lower-1, 2):  
	#print x
	timestamp1 = host1_hist[x]['ts']
	timestamp2 = host2_hist[x+1]['ts']
	ts1 = datetime.time(int(timestamp1.split(":")[0]), int(timestamp1.split(":")[1]), int(timestamp1.split(":")[2]))
	ts2 = datetime.time(int(timestamp2.split(":")[0]), int(timestamp2.split(":")[1]), int(timestamp2.split(":")[2]))

	#print "Comparing ts1 ("+timestamp1+") to ts2 ("+timestamp2+")"
	'''
	Right now we just check for matching timestamps.
	TODO: Allow for table rows that only have information for one host or the other
	'''
	if ts1 == ts2:
		#print colors.DBLUE + "Found matching timestamps"
		line_ts = timestamp1   # doesn't matter, same value
		#print line_ts
		health1 = host1_hist[x]['health']
		score1 = host1_hist[x]['score']
		if host1_hist[x]['runningVM']:
			vm1 = 'X'
		else:
			vm1 = '-'
		if host2_hist[x+1]['runningVM']:
			vm2 = 'X'
		else:
			vm2 = '-'
		score2 = host2_hist[x+1]['score']
		health2 = host2_hist[x+1]['health']
		print_table_row(line_ts,health1,score1,vm1,vm2,score2,health2)
	else:
		TS_FORMAT = '%H:%M:%S'
		# compare seconds in timestamp, allow a ~5s windows of time drift
		tsdelta = datetime.datetime.strptime(timestamp2, TS_FORMAT) - datetime.datetime.strptime(timestamp1, TS_FORMAT)
		#print "tdelta: " + str(tsdelta)
		#print "Found non-matching timestamps, comparing "+timestamp1+"s to "+timestamp2+"s"
		if tsdelta.seconds <= 5:
			line_ts = timestamp1   # doesn't matter, same(ish) value
			health1 = host1_hist[x]['health']
			score1 = host1_hist[x]['score']
			if host1_hist[x]['runningVM']:
				vm1 = 'X'
			else:
				vm1 = '-'
			if host2_hist[x+1]['runningVM']:
				vm2 = 'X'
			else:
				vm2 = '-'
			score2 = host2_hist[x+1]['score']
			health2 = host2_hist[x+1]['health']
			print_table_row(timestamp1,health1,score1,vm1,vm2,score2,health2)	
		#else: # check to see which has the earlier timestamp, print it first without host informating in opposite column
			#print "Greater than 5 second time skew, skipping"	

find_score_penalties(HOSTNAMES[0], ha_logs[0])
print "\n"
find_score_penalties(HOSTNAMES[1], ha_logs[1])
