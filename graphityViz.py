from pydotplus.graphviz import Node
import networkx as nx
import json
import os

from graphityScan import functionalityScan
import graphityFunc


def dumpGml(graphity):

	graphMl = graphity.copy()
	
	for node in graphMl.node:
		for attr in graphMl.node[node]:
			if type(graphMl.node[node][attr]) == list:
				listOfLists = graphMl.node[node][attr]
				seList = map(' '.join, listOfLists)
				graphMl.node[node][attr] = ' | '.join(seList)
				
	nx.write_gml(graphMl, "output/callgraph.gml")
	
	
	behaviorGraph = graphity.copy()
		
	allThePatterns = graphityFunc.funcDict
	allTheFindings = []
	for patty in allThePatterns:
		findings = functionalityScan(graphity, allThePatterns[patty])
		for hit in findings:
			if not False in hit['patterns'].values():
				for node in hit['patterns']:
					theNode = hit['patterns'][node]
					behaviorGraph.node[theNode][patty] = patty
	
	for node in behaviorGraph:
		del behaviorGraph.node[node]['calls']
		del behaviorGraph.node[node]['strings']
		behaviorGraph.node[node]['behaviors'] = ''
		for patty in allThePatterns:
			if behaviorGraph.node[node].get(patty):
				behaviorGraph.node[node]['behaviors'] += '|' + patty
		if behaviorGraph.node[node]['behaviors'] != '':
			behaviorGraph.node[node]['behaviors'] += '|'
				
	nx.write_gml(behaviorGraph, "output/behaviorgaddgets.gml")
	
	
	allocGraph = graphity.copy()
	for node in allocGraph.nodes():
		allocGraph.node[node]['allocs'] = 0
		
	allCalls = nx.get_node_attributes(allocGraph, 'calls')
	for function in allCalls:
		for call in allCalls[function]:
			if 'alloc' in call[1].lower():
				allocGraph.node[function]['allocs'] += 1
	
	for node in allocGraph:
		del allocGraph.node[node]['calls']
		del allocGraph.node[node]['strings']
	nx.write_gml(allocGraph, "output/allocgadgets.gml")

def dumpGmlSubgraph(graphity, address):

	theSub = nx.DiGraph()
	theSub.add_node(address, type='function', size=graphity.node[address]['size'], apicallcount=graphity.node[address]['apicallcount'])
	fetchExtendedSubgraph(graphity, theSub, address)
	gmlfile = "output/subgraph_" + address + ".gml"
	nx.write_gml(theSub, gmlfile)

	
def fetchExtendedSubgraph(graphity, theSub, address):
	
	for acall in graphity.node[address]['calls']:
		label = acall[0] + '|' + acall[1]
		theSub.add_node(label, type='api', apiname=acall[1])
		theSub.add_edge(address, label)
	
	for astring in graphity.node[address]['strings']:
		label = astring[0] + '|' + astring[1]
		theSub.add_node(label, type='string', string=astring[1])
		theSub.add_edge(address, label)
	
	neighbors = graphity.successors(address)
	
	for neigh in neighbors:
		theSub.add_node(neigh, type='function', size=graphity.node[neigh]['size'], apicallcount=graphity.node[neigh]['apicallcount']) # add attributes
		theSub.add_edge(address, neigh)
		fetchExtendedSubgraph(graphity, theSub, neigh)
		
	return
		

# Graph plotting with pydotplus from within NetworkX, format is dot
def graphvizPlot(graphity, allAtts):

	pydotMe = nx.drawing.nx_pydot.to_pydot(graphity)
	for node in pydotMe.get_nodes():

		# get node address to be able to fetch node directly from graphity to preserve data types of attributes
		nodeaddr = node.to_string().split()[0].replace('\"', '')
		finalString = ''
		
		if node.get('calls') != '[]' or node.get('strings') != '[]':
		
			finalList = []
			
			# fetching string and call lists directly from graphity
			callList = graphity.node[nodeaddr]['calls']
			stringList = graphity.node[nodeaddr]['strings']
			
			for item in callList:
				finalList.append(str(item[0]) + ": [C] " + str(item[1]))
			for otem in stringList:
				finalList.append(str(otem[0]) + ": [S] " + str(otem[1]))
			
			finalList.sort()
			finalString = '\n'.join(finalList)
			
		if node.get('functiontype') == 'Export':
			label = "Export " + nodeaddr + node.get('alias')
			label = label + "\n" + finalString
			node.set_fillcolor('skyblue')
			node.set_style('filled,setlinewidth(3.0)')
			node.set_label(label)

		elif node.get('functiontype') == 'Callback':
			label = "Callback " + nodeaddr + "\n" + finalString
			node.set_fillcolor('darkolivegreen1')
			node.set_style('filled,setlinewidth(3.0)')
			node.set_label(label)

		elif finalString != '':
			finalString = nodeaddr + "\n" + finalString
			node.set_fillcolor('lightpink1')
			node.set_style('filled,setlinewidth(3.0)')
			node.set_label(finalString)

	graphinfo = "SAMPLE " + allAtts['filename'] + "\nType: " + allAtts['filetype'] + "\nSize: " + str(allAtts['filesize']) + "\nMD5: " + allAtts['md5'] + "\nImphash:\t\t" + allAtts['imphash'] + "\nCompilation time:\t" + allAtts['compilationts'] + "\nEntrypoint section:\t" + allAtts['sectionep']

	titleNode = Node()
	titleNode.set_label(graphinfo)
	titleNode.set_shape('rectangle')
	titleNode.set_fillcolor('grey')
	titleNode.set_style('filled')
	pydotMe.add_node(titleNode)

	graphname = allAtts['filename'] + ".png"
	try:
		# TODO pydotplus throws an error sometimes (Error: /tmp/tmp6XgKth: syntax error in line 92 near '[') look into pdp code to see why
		pydotMe.write_png(os.path.join(os.path.abspath(os.path.dirname(__file__)), graphname))
	except Exception as e:
		print("ERROR drawing graph")
		print(str(e))


# Experimental Javascript InfoVis Tk data generation
def dumpJsonForJit(graphity, indent=None):

	json_graph = []
	for node in graphity.nodes():
		json_node = {
			'id': node,
			'name': node
		}
		# node data
		json_node['data'] = graphity.node[node]
		
		# Style
		if graphity.node[node].get('calls') != []:
			json_node['data']['$color'] = '#FFFF00' # yellow
			
		if graphity.node[node].get('functiontype') == 'Callback':
			json_node['data']['$dim'] = 8
			json_node['data']['$type'] = 'square'
			json_node['data']['$color'] = '#FF0080' # pink
			json_node['name'] = node + " Callback"
		
		if graphity.node[node].get('functiontype') == 'Export':
			json_node['data']['$dim'] = 8
			json_node['data']['$type'] = 'square'
			json_node['data']['$color'] = '#3ADF00' # green
			json_node['name'] = node + " Export"

		
		# adjacencies
		if graphity[node]:
			json_node['adjacencies'] = []
			
			for neighbour in graphity[node]:
				adjacency = {'nodeTo': neighbour}
				# adjacency data
				adjacency['data'] = graphity.edge[node][neighbour]
				json_node['adjacencies'].append(adjacency)
		#print (json_node)
		json_graph.append(json_node)

	#print(json.dumps(json_graph, indent=indent))
	return json.dumps(json_graph, indent=indent)

