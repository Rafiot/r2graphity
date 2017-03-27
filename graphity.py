#!/usr/bin/env python

import r2pipe
import sys
import os
import json
import re
import networkx as nx
from time import time
from datetime import datetime
from argparse import ArgumentParser
from base64 import b64decode
from graphityOut import toNeo, fromNeo, printGraph, printGraphInfo, dumpGraphInfoCsv, toPickle, fromPickle
from graphityViz import graphvizPlot, dumpJsonForJit, dumpGml, dumpGmlSubgraph
from graphityUtils import gimmeDatApiName, sha1hash, getAllAttributes, is_ascii, Hvalue, check_pe_header
from graphityScan import functionalityScan
import graphityFunc


# Works, takes its time, sometimes assigns wrong names to functions
def loadFlirts():

	try:
		# load FLIRT signatures from local flirt directory
		flirtDir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'signatures')
		sigFiles = [f for f in os.listdir(flirtDir) if os.path.isfile(os.path.join(flirtDir, f))]

		for sigFile in sigFiles:
			r2cmd = "zF %s" % os.path.join(flirtDir, sigFile)
			R2PY.cmd(r2cmd)

	except Exception as e:
		print(str(e) + " FAIL loading FLIRT sig file")


# Too slow for now, waiting for fix
# DEPRECATED
def loadZigs():

	try:
		# load directory of zigs
		print('Loading msvcrt.zig {:%Y-%m-%d %H:%M:%S}'.format(datetime.now()))

		zigfile = '/mnt/hgfs/projects/badcoding/R2PYpe/libs/msvcrt.zig'
		r2cmd = ". %s" % zigfile
		R2PY.cmd(r2cmd)

		print('msvcrt.zig loaded {:%Y-%m-%d %H:%M:%S}'.format(datetime.now()))

		toScan = getCodeSections()
		for section in toScan:
			r2cmd = ".z/ %d %d" % (section[0], section[1])
			R2PY.cmd(r2cmd)

		print('msvcrt.zig scan on code section(s) finished {:%Y-%m-%d %H:%M:%S}'.format(datetime.now()))

	except Exception as e:
		print(str(e))


# Checks whether an address is located in an executable section
def isValidCode(callAddress, sectionsList):

	# sectionsList contains executable sections as 2-element lists, containing start and end of each section
	for execSection in sectionsList:
		if int(callAddress, 16) >= execSection[0] and int(callAddress, 16) < execSection[1]:
			return True
	return False


# Returns a list of executable sections
def getCodeSections():

	returnSections = []

	# regular expression to pick out the executable section(s)
	execSection = re.compile("perm=....x")

	# will return the section table from radare2
	sections = R2PY.cmd("iS")

	sectionData = {}

	for line in sections.splitlines():
		if re.search(execSection, line):
			for element in line.split():
				items = element.split('=')
				sectionData[items[0]] = items[1]

			start = int(sectionData['vaddr'], 16)
			end = start + int(sectionData['vsz'])
			psize = int(sectionData['sz'])
			returnSections.append([start, end, psize])

	return returnSections


# Returns an executables imports as a list
def getIat():

	iatlist = []
	cmd = "iij"
	iatjson = json.loads(R2PY.cmd(cmd))
	for item in iatjson:
		iatlist.append(hex(item['plt']))
	return iatlist


# Returns a dictionary of xrefs to symbols
def crossRefScan():

	cmd = "axtj @@ sym.*"
	finalCalls = {}

	# fixing the JSON... issue reported to radare2, keep in mind to remove workaround
	temp = R2PY.cmd(cmd).replace('\n', ',')
	temp = "[" + temp + "]"

	xrefj = json.loads(temp)
	# TODO check!!

	for xrefitem in xrefj:
		for xreflevel2 in xrefitem:

			# not data xref means its code or call
			if xreflevel2['type'] != 'd':
				finalCalls[hex(xreflevel2['from'])] = xreflevel2['opcode']
				pass

			# data potentially means API referenced by register; please note these are rather uncommon in the long list of symbol refs
			# thus, bottelneck in parsing speed lies in number of refs
			if xreflevel2['type'] == 'd' and ( xreflevel2['opcode'].startswith('mov') or xreflevel2['opcode'].startswith('lea') ):

				# 'grepping' out the register from mov/lea operation
				register = xreflevel2['opcode'].split()[1].replace(',','')

				# disassemble downwards; mmmaybe smarter to disassemble until end of function, but possible that there is no function at all
				# TODO find end of function, just in case
				cmd = "pd 300 @ " + hex(xreflevel2['from'])
				moreDisasm = R2PY.cmd(cmd)

				# possible branches towards target
				realCall = "call %s" % register
				aJmp = "jmp %s" % register

				for disasmLine in moreDisasm.splitlines()[1:]:
					if realCall in disasmLine or aJmp in disasmLine:
						#found a call!!
						temp = disasmLine + ";" + xreflevel2['opcode'].split(',')[1].rstrip()
						tempSplit = temp.split()
						finalCalls[hex(int(tempSplit[0], 16))] = ' '.join(tempSplit[1:])

					elif register in disasmLine:
						# TODO if mov dword abc, reg is found -> follow abc?
						# TODO could be parsed in more detail, e.g. mov dword, reg won't change the reg
						#print disasmLine

						break
						#pass
	return finalCalls


# Parses the binary for strings and their references to nodes
def stringScan(debugDict):

	# Workflow is: get string, get xrefs to string if any, get functions of xrefs if any; fit node in graph with the string
	allMyStrings = []

	# izzj parses entire binary
	stringCmd = "izzj"
	strings = R2PY.cmd(stringCmd)
	#print (strings)
	parsedStrings = json.loads(strings)

	debugDict['stringsDangling'] = []
	debugDict['stringsNoRef'] = []

	i = 0
	j = 1
	while i < len(parsedStrings):
		stringItem = parsedStrings[i]

		# Strings when retrieved through izzj command are BASE64 encoded
		thatOneString = b64decode(stringItem['string']).replace(b'\\', b' \\\\ ')
		thatOneString.replace(b'\'', b'')
		
		try:
			thatOneString = thatOneString.decode()
		
			xrefCmd = "axtj @ " + hex(stringItem['vaddr'])
			stringXrefsJ = R2PY.cmd(xrefCmd)

			if stringXrefsJ:
				stringXrefs = json.loads(stringXrefsJ)

				# check whether string item is root of list of strings
				j = 1
				lastItem = stringItem
				while (i + j) < len(parsedStrings):
					nextStringItem = parsedStrings[i + j]
					lastAddr = lastItem['vaddr']
					lastSize = lastItem['size']

					# string offsets are 4 byte aligned, TODO check whether this is always the case
					padding = 4 - (lastSize % 4)
					if padding == 4:
						padding = 0
					nextAddr = lastAddr + lastSize + padding

					if nextAddr != nextStringItem['vaddr'] or hasXref(hex(nextStringItem['vaddr'])):
						# end.. exit here
						break
					else:
						thatOneString = thatOneString + "|" + b64decode(nextStringItem['string']).decode()
						j = j + 1
						lastItem = nextStringItem

				# iterate refs on string, if any
				for ref in stringXrefs:
					stringAddr = hex(ref['from'])
					stringFuncRefCmd = "?v $FB @ " + stringAddr
					stringFuncRef = R2PY.cmd(stringFuncRefCmd)
					if stringFuncRef != '0x0':
						allMyStrings.append([stringAddr, stringFuncRef, thatOneString])
						#print (thatOneString)
					else:
						# TODO this is merely still useful strings, see how to fit them in the graphs and db
						# NOTE: with character frequency analysis we could filter for useful strings here, reduce data, add to graph?
						print("DANGLING STRING NO FUNCREF %s %s" % (stringAddr, thatOneString))
						debugDict['stringsDangling'].append(thatOneString)
						
			else:
				debugDict['stringsNoRef'].append(thatOneString)
						

		except UnicodeDecodeError:
			pass
		if j > 1:
			i = i + j
		else:
			i = i + 1

	debugDict['stringsDanglingTotal'] = len(debugDict['stringsDangling'])
	debugDict['stringsNoRefTotal'] = len(debugDict['stringsNoRef'])
	return allMyStrings


# Text whether xrefs exist for given address
def hasXref(vaddr):

	refs = R2PY.cmd("axtj @ " + vaddr)
	if refs:
		return True
	else:
		return False


# Creating the NetworkX graph, nodes are functions, edges are calls or callbacks
def createRawGraph():

	graphity = nx.DiGraph()
	debugDict = {}

	functions = R2PY.cmd("aflj")
	if functions:
		functionList=json.loads(functions)
		#print json.dumps(functionList, indent=4, sort_keys=True)
	else:
		functionList = []

	# figuring out code section size total
	sectionsList = getCodeSections()
	xlen = 0
	for execSec in sectionsList:
		xlen = xlen + execSec[2]
	debugDict['xsectionsize'] = xlen

	# CREATING THE GRAPH

	refsGlobalVar = 0
	refsUnrecognized = 0
	refsFunc = 0
	debugDict['functions'] = len(functionList)

	### NetworkX Graph Structure ###

	# FUNCTION as node, attributes: function address, size, calltype, list of calls, list of strings, count of calls; functiontype[Callback, Export], alias (e.g. export name)
	# FUNCTIoN REFERENCE as edge (function address -> target address), attributes: ref offset (at)
	# CALLBACK REFERENCE as edge (currently for threads and Windows hooks)
	# API CALLS (list attribute of function node): address, API name
	# STRINGS (list attribute of function node): address, string

	####

	for item in functionList:

		#print hex(item['offset'])
		graphity.add_node(hex(item['offset']), size=item['size'], calltype=item['calltype'], calls=[], apicallcount=0, strings=[], functiontype='')

	for item in functionList:

		# TODO look into new values provided by aflj
		for xref in item['callrefs']:

			if xref['type'] == 'C':

				# If an edge is added, that includes a non-existent node, the node will be added, but w/o the necessary attributes
				# Thasss why we iterate twice, can theoretically be speeded up but needs testing
				if hex(xref['addr']) in graphity:
					if item['offset'] != xref['addr']:
						graphity.add_edge(hex(item['offset']), hex(xref['addr']), pos=hex(xref['at']))
						refsFunc = refsFunc + 1

				elif hex(xref['addr']) in getIat():
					pass

				elif not isValidCode(hex(xref['addr']), sectionsList):
					print("DANGLING call to address outside code section, glob var, dynamic API loading %s -> %s" % (hex(item['offset']), hex(xref['addr'])))
					refsGlobalVar = refsGlobalVar + 1

				else:
					print("FAIL: Call to code thats not a function, an import/symbol or otherwise recognized. Missed function perhaps. %s -> %s" % (hex(item['offset']), hex(xref['addr'])))
					refsUnrecognized = refsUnrecognized + 1

	print('* %s Graph created with NetworkX ' % str(datetime.now()))
	debugDict['refsFunctions'] = refsFunc
	debugDict['refsGlobalVar'] = refsGlobalVar
	debugDict['refsUnrecognized'] = refsUnrecognized

	#loadFlirts()
	apiRefs = crossRefScan()

	callNum = len(apiRefs)
	missesNum = 0

	# FITTING GRAPH WITH API REFS

	for call in apiRefs:

		# get the address of the function, that contains the call to a given symbol
		refAddressCmd = "?v $FB @ " + call
		funcAddress = R2PY.cmd(refAddressCmd)

		# TODO check if funcAddress is the real function address
		if funcAddress in graphity:

			# node(funcAddress) has attribute calls, which contains a list of API calls
			api = gimmeDatApiName(apiRefs[call])

			graphity.node[funcAddress]['calls'].append([call, api])
			apicount = graphity.node[funcAddress]['apicallcount']
			graphity.node[funcAddress]['apicallcount'] = apicount + 1

		# detected API call reference does not resolve to a function offset, insert handling for this here
		else:
			print("DANGLING API CALL %s %s" % (call, apiRefs[call]))
			missesNum = missesNum+1

	# debug: print total API refs and functionless API refs, maybe indicator for obfuscated code
	print('* %s Graph extended with API calls, %d calls in total, %d dangling w/o function reference ' % (str(datetime.now()), callNum, missesNum))
	debugDict['apiTotal'] = callNum
	debugDict['apiMisses'] = missesNum


	# FITTING GRAPH WITH STRING REFS

	allTheStrings = stringScan(debugDict)
	stringrefs = 0

	for aString in allTheStrings:

		stringAddr = aString[0]
		stringFunc = aString[1]
		stringData = aString[2]

		# add string to respective function node in graph
		if stringFunc in graphity:
			graphity.node[stringFunc]['strings'].append([stringAddr, stringData])
			stringrefs = stringrefs + 1

		else:
			print("\n*** BIG FAIL *** String's function not in graph %s %s" % (stringFunc, stringData))

	print('* %s Graph extended with string references ' % (str(datetime.now())))
	debugDict['stringsReferencedTotal'] = stringrefs

	return graphity, debugDict


# Tag exports of DLLs
# TODO : check whether exports are coming back after bugfix (?)
def analyzeExports(graphity):

	exportsj = json.loads(R2PY.cmd("iEj"))
	for item in exportsj:

		exportAddress = hex(item['vaddr'])
		exportName = item['name']

		exportFunction = gimmeRespectiveFunction(exportAddress)

		if exportFunction in graphity:
			graphity.node[exportFunction]['functiontype'] = 'Export'
			graphity.node[exportFunction]['alias'] = exportName


# Removing thunks as they make my graphs fat, replace by API calls
def thunkPruning(graphity):

	for aNode in graphity.nodes(data=True):

		# most obvious thunks, other thunks exist too, len seen was 11, 13
		# funclets that contain nothing but a jump to an import, and do not call other functions
		if aNode[1]['apicallcount'] == 1 and aNode[1]['size'] == 6 and not graphity.successors(aNode[0]):

			thunk = aNode[0]
			thunkApi = aNode[1]['calls'][0]

			# need to go on with radare from here, cause graphity doesn't know all the addressed of the xrefs to thunks from within a function
			# getting all xrefs on thunk, then getting function its located in to get to node of graph
			temp = R2PY.cmd("axtj " + thunk)

			thunkRefs = []
			if temp:
				thunkRefs = json.loads(temp)

			for aRef in thunkRefs:

				thunkCallAddr = hex(aRef['from'])
				thunkFuncRef = R2PY.cmd("?v $FB @ " + hex(aRef['from']))

				# if thunk's xrefs include a detected function then add thunk as a regular API call to calls list of respective node
				if thunkFuncRef != '0x0':
					graphity.node[thunkFuncRef]['calls'].append([thunkCallAddr, thunkApi[1]])

			# after xref to thunk has been added to all calling functions, remove thunk node from graph
			graphity.remove_node(thunk)


# DEPRECATED
def fixCallbacks(apiname):

	cmd = "axtj @@ sym.* | grep \"%s\"" % apiname
	temp = R2PY.cmd(cmd).replace(']\n[', ',')

	if temp:
		callbackApis = json.loads(temp)
		for item in callbackApis:
			function = R2PY.cmd("?v $FB @ " + hex(item['from']))
			R2PY.cmd("afr @ " + function)


# Adding edges to indirectly referenced functions, thread handlers and hook functions for now only
def tagCallbacks(graphity):

	callbackList = []
	for aNode in graphity.nodes(data=True):
		for call in aNode[1]['calls']:

			addr = ''
			# TODO consider this bad practise, do something smarter, not sure yet what,  consider _beginthread API etc. etc.
			# also, maybe this is fixed in radare later, so consider this code redundant by then
			if 'CreateThread' in call[1]:
				addr = getCallback(call[0], 3)
				
			if 'SetWindowsHookEx' in call[1]:
				addr = getCallback(call[0], 2)

			function = gimmeRespectiveFunction(addr)
			
			if function in graphity:
				graphity.node[function]['functiontype'] = "Callback"
				graphity.add_edge(aNode[0], function, pos=call[0], calltype="callback")


# Parsing the handler offset out of the function arguments
def getCallback(call, argcount):

	# simplistic: walk up the code until xref to code is found, works as long as API only receives one code ref, works well with Windows APIs
	disasmMore = "pd -30 @" + call
	upwards = R2PY.cmd(disasmMore)

	for otherLine in reversed(upwards.splitlines()):
		if 'push' in otherLine:
			argcount = argcount - 1

		# TODO better done with a regex, bug prone
		if not argcount:
			address = otherLine.split("push",1)[1].split()[0]
			if 'fcn.' in address:
				return hex(int(address.split('.')[1], 16))
			if '0x' in address:
				return hex(int(address.split('0x')[1], 16))
			else:
				return ''


# WORKAROUND until function detection - bug? feature? in radare is fixed and export vaddr equal actual offsets again
def gimmeRespectiveFunction(address):
	if address:
		return R2PY.cmd("?v $FB @ " + address)
	return ''


# super graph creation function, radare-analyses the sample, puts together all of the graph and debug info
def graphMagix(filepath, allAtts, deactivatecache):

	global R2PY

	if (os.path.isfile("cache/" + allAtts['sha1'] + ".txt") and os.path.isfile("cache/" + allAtts['sha1'] + ".dbg") and deactivatecache == False):
		print('* %s Loading graph from cache under ./cache/[sha1].txt or .dbg' % str(datetime.now()))
		graphity, debug = fromPickle(allAtts['sha1'])

	else:
		print('* %s R2 started analysis ' % str(datetime.now()))

		BENCH['r2_start'] = time()

		R2PY = r2pipe.open(filepath)

		R2PY.cmd("e asm.lines = false")
		R2PY.cmd("e asm.fcnlines = false")
		R2PY.cmd("e anal.autoname= false")
		R2PY.cmd("e anal.jmptbl = true")
		R2PY.cmd("e anal.hasnext = true")
		R2PY.cmd("aaa")
		R2PY.cmd("afr")
		R2PY.cmd("afr @@ sym*")

		BENCH['r2_end'] = time()
		print('* %s R2 finished analysis' % str(datetime.now()))

		# GRAPH CREATION
		graphity, debug = createRawGraph()

		# DLL PROCESSING
		if 'DLL' in allAtts['filetype']:
			analyzeExports(graphity)

		# Thunk pruning, thunks are unnecessary information in the graph
		thunkPruning(graphity)

		# handler tagging
		tagCallbacks(graphity)

		BENCH['graph_end'] = time()

		# graph and debug info caching to save parsing time, potentially
		if (deactivatecache == False):
			toPickle(graphity, debug, allAtts['sha1'])

	return graphity, debug


if __name__ == '__main__':

	#global R2PY
	global BENCH
	BENCH = {}

	parser = ArgumentParser()
	parser.add_argument("input", help="Tool requires an input file or directory; directory, i.e. batch processing, only possible and feasible for csvdump option")
	parser.add_argument("-d", "--deactivatecache", action="store_true", help="Deactivate caching of graphs, for debugging of graph generation")
	parser.add_argument("-p", "--printing", action="store_true", help="Print the graph as text, as in, nodes with respective content")
	parser.add_argument("-i", "--info", action="store_true", help="Print info and stats of the graph")
	parser.add_argument("-l", "--plotting", action="store_true", help="Plotting the graph via pyplot")
	parser.add_argument("-b", "--behavior", action="store_true", help="Scan for behaviors listed in graphityFunc.py")
	parser.add_argument("-n", "--neodump", action="store_true", help="Dump graph to Neo4j (configured to flush previous data from Neo, might wanna change that)")
	parser.add_argument("-c", "--csvdump", help="Dump info data to a given csv file, appends a line per sample")

	args = parser.parse_args()
	# TODO check the path pythonically

	# Batch processing options: csvdump, neodump, TBC

	if args.input and os.path.isdir(args.input):

		for (dirpath, dirnames, filenames) in os.walk(args.input):
			for filename in filenames:
				filepath = os.path.join(dirpath, filename)

				if check_pe_header(filepath):

					print('* %s Parsing %s ' % (str(datetime.now()), filename))

					allAtts = getAllAttributes(filepath)
					graphity, debug = graphMagix(filepath, allAtts, args.deactivatecache)

					if args.csvdump:
						# CSVDUMP
						dumpGraphInfoCsv(graphity, debug, allAtts, args.csvdump)
						print('* %s Dumping graph info to indicated csv file ' % str(datetime.now()))

					if args.neodump:
						# TO NEO STUFF
						toNeo(graphity, allAtts)
						print('* %s Dumped to Neo4J ' % str(datetime.now()))

	elif args.input and check_pe_header(args.input):

		# ATTRIBUTES: md5, sha1, filename, filetype, ssdeep, filesize, imphash, compilationts, addressep, sectionep,
		# sectioncount, sectioninfo, tlssections, originalfilename

		allAtts = getAllAttributes(args.input)
		graphity, debug = graphMagix(args.input, allAtts, args.deactivatecache)
		
		# TODO decide what to do with dangling strings/APIs (string filtering with frequency analysis?)


		if args.printing:
			# PRINT GRAPH TO CMDLINE
			print("* %s Printing the graph - nodes and node attributes" % str(datetime.now()))
			BENCH['printing_start'] = time()
			printGraph(graphity)
			BENCH['printing_end'] = time()

		if args.info:
			# PRINT GRAPH INFO
			BENCH['info_start'] = time()
			printGraphInfo(graphity, debug)
			BENCH['info_end'] = time()

			# TODO look into certificate info: iC

		if args.plotting:
			# GRAPH PLOTTING STUFF
			#try:
			print('* %s Plotting routine starting ' % str(datetime.now()))
			BENCH['plotting_start'] = time()
			graphvizPlot(graphity, allAtts)
			BENCH['plotting_end'] = time()
			print('* %s Plotting routine finished ' % str(datetime.now()))
			#except:
			#	   print '* %s Cant plot this with pydot, too big ' % str(datetime.now())

		if args.neodump:
			# TO NEO STUFF
			BENCH['neo_start'] = time()
			toNeo(graphity, allAtts)
			BENCH['neo_end'] = time()
			print('* %s Dumped to Neo4J ' % str(datetime.now()))

		if args.behavior:
			# BEHAVIOR
			print('* %s Scanning for API patterns ' % str(datetime.now()))
			BENCH['behavior_start'] = time()
			allThePatterns = graphityFunc.funcDict

			for patty in allThePatterns:
				findings = functionalityScan(graphity, allThePatterns[patty])

				for hit in findings:
					if not False in hit['patterns'].values():
						print("For %s found %s" % (patty, str(hit['patterns'])))
			BENCH['behavior_end'] = time()



			# TODO calculate dispersion for 2-n anchor addresses
			# TODO handling of LoadLib/GetPAddr. for "hiding something" question, follow GetProc return value


		print('* %s Stuffs all finished ' % str(datetime.now()))

		# TIME
		print("\n__..--*** I WANNA BE A BENCHMARK WHEN I GROW UP ***--..__")

		if 'r2_start' in BENCH:
			print("__ %5f R2 Analysis" % (BENCH['r2_end'] - BENCH['r2_start']))
		if 'graph_end' in BENCH:
			print("__ %5f Graph construction" % (BENCH['graph_end'] - BENCH['r2_end']))

		if 'printing_start' in BENCH:
			print("__ %5f Printing" % (BENCH['printing_end'] - BENCH['printing_start']))
		if 'info_start' in BENCH:
			print("__ %5f Info" % (BENCH['info_end'] - BENCH['info_start']))
		if 'plotting_start' in BENCH:
			print("__ %5f Plotting" % (BENCH['plotting_end'] - BENCH['plotting_start']))
		if 'behavior_start' in BENCH:
			print("__ %5f Behavior" % (BENCH['behavior_end'] - BENCH['behavior_start']))
		if 'neo_start' in BENCH:
			print("__ %5f Neo4j" % (BENCH['neo_end'] - BENCH['neo_start']))
		if 'csv_start' in BENCH:
			print("__ %5f CSV dump" % (BENCH['csv_end'] - BENCH['csv_start']))

	else:
		print("Potentially not a PE file %s" % args.input)


