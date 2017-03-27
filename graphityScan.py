import networkx as nx
import graphityFunc


# searching nodes and nearby nodes for patterns defined by graphityFunc.py
def functionalityScan(graphity, pattern):

	# search is performed by defining "anchor" node, where initial pattern is found
	# search then moved from there 1 level up to search surrounding nodes (number of levels could be increased)
	# pattern lists for now are kept rather small
	# TODO determine distance between found patterns to see which functionalities lie close to each other
	patternNum = len(pattern)
	anchorList = []

	allCalls = nx.get_node_attributes(graphity, 'calls')

	for function in allCalls:
	
		# TODO make this prettier!
		# apis = [el[1] for el in allCalls[function]]
		# if 'CreateThread' in apis:
		# 	print (function)
			
		for call in allCalls[function]:

			api = call[1]
			anchorpat = pattern[0]

			if anchorpat in api:
				if not list(filter(lambda daAnchor: daAnchor['address'] == function, anchorList)):
					
					# maintain a dict of patterns per anchor to keep track of found patterns
					patternCheck = {}
					for item in pattern:
						patternCheck[item] = False
					patternCheck[anchorpat] = function

					anchorList.append({'address':function, 'patterns':patternCheck})

	# anchor nodes found and more than one pattern searched for
	if patternNum > 1 and len(anchorList) > 0:
		for anchor in anchorList:

			scanNodeForApi(graphity, anchor, anchor['address'], patternNum)
			if False in anchor['patterns'].values():

				anchorNeighbors = nx.all_neighbors(graphity, anchor['address'])
				for neighbor in anchorNeighbors:
					scanNodeForApi(graphity, anchor, neighbor, patternNum)

	return anchorList


# Search for a specific pattern within a node, orient by anchor pattern
def scanNodeForApi(graphity, anchor, seNode, patternNum):

	for patt in anchor['patterns']:

		# anchor has a dict that saves which patterns were found already
		for call in graphity.node[seNode]['calls']:
			api = call[1]

			# found a pattern in an api call, that hasnt been found before
			if patt in api and anchor['patterns'][patt] == False:
				anchor['patterns'][patt] = seNode

				if not False in anchor['patterns'].values():
					# all patterns found - done
					break
					
					
					
					