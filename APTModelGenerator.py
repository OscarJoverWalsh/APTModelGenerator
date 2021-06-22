import sqlite3

from stix2 import AttackPattern
from stix2 import Malware
from stix2 import Tool

from stix2 import Bundle
from stix2 import Relationship
from stix2 import parse

#########################################################################################

NAttP = input("Enter number of Attack-Patterns:")
#Phases = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]
n = 0
i = 0
x = 0

attackPatternTypes = []
attackPatternId = []
attackPatternCreated = []
attackPatternModified = []
attackPatternNames = []
attackPatternDescriptions = []
attackPatternPhaseNames = []
attackPatternPhaseNumber = []

subAttackPatternTypes = []
subAttackPatternId = []
subAttackPatternCreated = []
subAttackPatternModified = []
subAttackPatternNames = []
subAttackPatternDescriptions = []
subAttackPatternPhaseNames = []

malwareTypes = []
malwareId = []
malwareCreated = []
malwareModified = []
malwareNames = []
malwareDescriptions = []

toolTypes = []
toolId = []
toolCreated = []
toolModified = []
toolNames = []
toolDescriptions = []

relationshipType = []
relationshipSourceRefs = []
relationshipTargetRefs = []
relationshipDescriptions = []

relationshipMT_APType = []
relationshipSourceMT_APRefs = []
relationshipTargetMT_APRefs = []
relationshipMT_APDescriptions = []

relationshipAPType = []
relationshipSourceAPRefs = []
relationshipTargetAPRefs = []
relationshipAPDescriptions = []

#########################################################################################

#Open bundle 
db_file = "C:/Users/oscar/ATTACK-Tools-master/attack_view_db.sqlite" # path to the local db file 
conn = None

try:
    conn = sqlite3.connect(db_file)
except Error as e:
    print (e)

f = open("APTModelGenerated.json", "w")
print ('{', file= f)
print ('"type": "bundle",', file= f)
print ('"id": "bundle--f7cdadd5-24c2-49ee-afbc-a807d33dc5dd",', file= f)
print ('"objects": [', file= f)
f.close()

#########################################################################################

#Attack-patterns
attackPatternCur = conn.cursor()
attackPatternCur .execute("SELECT type, kcp.fk_object_id, created, modified, sdos_object.name, sdos_object.description, phase_name, phase_number FROM sdos_object INNER JOIN kill_chain_phases kcp on sdos_object.id = kcp.fk_object_id WHERE kcp.fk_object_id LIKE '%attack-pattern%' ORDER BY RANDOM() LIMIT ?",  (NAttP,))
attackPatternRows = attackPatternCur.fetchall()
n = 0
for row in attackPatternRows:
	while row[6] not in attackPatternPhaseNames:
		attackPatternTypes.append(row[0])
		attackPatternId.append(row[1])
		attackPatternCreated.append(row[2])
		attackPatternModified.append(row[3])
		attackPatternNames.append(row[4])
		attackPatternDescriptions.append(row[5])
		attackPatternPhaseNames.append(row[6])
		attackPatternPhaseNumber.append(row[7])

i = 0
while i < len(attackPatternPhaseNames):
	attackPattern = AttackPattern(
		id= attackPatternId[i],
		created= attackPatternCreated[i],
		modified= attackPatternModified[i],
		name= attackPatternNames[i],
		description= attackPatternDescriptions[i],
		kill_chain_phases= [
	        {
	            "kill_chain_name": "mandiant-attack-lifecycle-model",
	            "phase_name": attackPatternPhaseNames[i]
	        }
	    ]
	)
	f = open("APTModelGenerated.json", "a")
	if i < len(attackPatternPhaseNames):
		print (attackPattern, ',', file=f)
	i = i + 1

#########################################################################################

#Sub-Attack-patterns
i = 0
for row in attackPatternId:
	subAttackPatternCur = conn.cursor()
	subAttackPatternCur .execute("SELECT type, kcp.fk_object_id, created, modified, sdos_object.name, sdos_object.description, phase_name FROM sdos_object INNER JOIN relationship r on sdos_object.id = r.source_ref INNER JOIN kill_chain_phases kcp on sdos_object.id = kcp.fk_object_id WHERE r.relationship_type = 'subtechnique-of' AND target_ref = ? GROUP BY source_ref ORDER BY phase_name", (row,))
	subAttackPatternRows = subAttackPatternCur .fetchall()

	for row in subAttackPatternRows:
		while row[1] not in subAttackPatternId:
			subAttackPatternTypes.append(row[0])
			subAttackPatternId.append(row[1])
			subAttackPatternCreated.append(row[2])
			subAttackPatternModified.append(row[3])
			subAttackPatternNames.append(row[4])
			subAttackPatternDescriptions.append(row[5])
			subAttackPatternPhaseNames.append(row[6])

	while i < len(subAttackPatternRows):
		subAttackPattern = AttackPattern(
			id= subAttackPatternId[i],
			created= subAttackPatternCreated[i],
			modified= subAttackPatternModified[i],
			name= subAttackPatternNames[i],
			description= subAttackPatternDescriptions[i],
			kill_chain_phases= [
		        {
		            "kill_chain_name": "mandiant-attack-lifecycle-model",
		            "phase_name": subAttackPatternPhaseNames[i]
		        }
		    ]
		)
		f = open("APTModelGenerated.json", "a")
		if i < len(subAttackPatternRows):
			print (subAttackPattern, ',', file=f)
		i = i + 1

#########################################################################################

#Malware
i = 0
for row in attackPatternId:
	malwareCur = conn.cursor()
	malwareCur.execute("SELECT type, sdos_object.id, created, modified, sdos_object.name, sdos_object.description FROM sdos_object INNER JOIN relationship r on sdos_object.id = r.source_ref WHERE r.source_ref LIKE '%malware%' AND r.target_ref = ? GROUP BY sdos_object.id",  (row,))
	malwareRows = malwareCur.fetchall()

	for row in malwareRows:
		while row[1] not in malwareId:
			malwareTypes.append(row[0])
			malwareId.append(row[1])
			malwareCreated.append(row[2])
			malwareModified.append(row[3])
			malwareNames.append(row[4])
			malwareDescriptions.append(row[5])
	
	while i < len(malwareRows):
		malware = Malware(
			id= malwareId[i],
			created= malwareCreated[i],
			modified= malwareModified[i],
			name= malwareNames[i],
			description= malwareDescriptions[i],
			is_family= False
		)
		f = open("APTModelGenerated.json", "a")
		if i < len(malwareRows):
			print (malware, ',', file=f)
		f.close()
		i = i + 1

#########################################################################################

#Tools
i = 0
for row in attackPatternId:
	toolCur = conn.cursor()
	toolCur.execute("SELECT type, sdos_object.id, created, modified, sdos_object.name, sdos_object.description FROM sdos_object INNER JOIN relationship r on sdos_object.id = r.source_ref WHERE r.source_ref LIKE '%tool%' AND r.target_ref = ? GROUP BY sdos_object.id",  (row,))
	toolRows = toolCur.fetchall()

	for row in toolRows:
		while row[1] not in toolId:
			toolTypes.append(row[0])
			toolId.append(row[1])
			toolCreated.append(row[2])
			toolModified.append(row[3])
			toolNames.append(row[4])
			toolDescriptions.append(row[5])

	while i < len(toolId):
		tool = Tool(
			id= toolId[i],
			created= toolCreated[i],
			modified= toolModified[i],
			name= toolNames[i],
			description= toolDescriptions[i]
		)
		f = open("APTModelGenerated.json", "a")
		if i < len(toolId):
			print (tool, ',', file=f)
		i = i + 1

#########################################################################################

#Relatioships
#Malware & Tool | Attack-pattern relationship
n = 0
mt_ap = malwareId + toolId + subAttackPatternId
mt_apCur = conn.cursor()
mt_apQuery = 'SELECT relationship_type, source_ref, target_ref, relationship.description, so.name, so.description FROM relationship INNER JOIN sdos_object so ON relationship.target_ref = so.id WHERE '

while n < len(attackPatternId):
	if (n < len(attackPatternId) - 1):
		mt_apQuery = mt_apQuery + "relationship.source_ref LIKE '%malware%' AND relationship.target_ref IS '" + str(attackPatternId[n]) + "' OR relationship.source_ref LIKE '%tool%' AND relationship.target_ref IS '" + str(attackPatternId[n]) + "' OR relationship.source_ref LIKE '%attack-pattern%' AND relationship.target_ref IS '" + str(attackPatternId[n]) + "' OR "
	else:
		mt_apQuery = mt_apQuery + "relationship.source_ref LIKE '%malware%' AND relationship.target_ref IS '" + str(attackPatternId[n]) + "' OR relationship.source_ref LIKE '%tool%' AND relationship.target_ref IS '" + str(attackPatternId[n]) + "' OR relationship.source_ref LIKE '%attack-pattern%' AND relationship.target_ref IS '" + str(attackPatternId[n]) + "' GROUP BY source_ref;"
	n = n + 1
mt_apCur.execute(mt_apQuery)
mt_apRows = mt_apCur.fetchall()

for row in mt_apRows:
	while row[1] not in relationshipSourceMT_APRefs:
		relationshipMT_APType.append(row[0])
		relationshipSourceMT_APRefs.append(row[1])
		relationshipTargetMT_APRefs.append(row[2])
		relationshipMT_APDescriptions.append(row[3])

i = 0
while i < len(mt_apRows):
	relationshipMT_AP = Relationship(
		relationship_type= relationshipMT_APType[i],
		source_ref= relationshipSourceMT_APRefs[i],
		target_ref= relationshipTargetMT_APRefs[i],
		description= relationshipMT_APDescriptions[i]
	)
	f = open("APTModelGenerated.json", "a")
	if i < len(mt_apRows):
		print (relationshipMT_AP, ',', file=f)
	f.close()
	i = i + 1

#########################################################################################

#Relatioships
#Attack-patter | Attack-pattern relationship
x = 0
n = 1
relationshipSourceAPRefs = attackPatternId
for row in attackPatternPhaseNumber:
	while x < len(attackPatternPhaseNumber):
		while attackPatternPhaseNumber[n-1] > attackPatternPhaseNumber[n]:
			attackPatternPhaseNumber[n-1], attackPatternPhaseNumber[n] = attackPatternPhaseNumber[n], attackPatternPhaseNumber[n-1]
			relationshipSourceAPRefs[n-1], relationshipSourceAPRefs[n] = relationshipSourceAPRefs[n], relationshipSourceAPRefs[n-1]
		n = n + 1
		if n == len(attackPatternPhaseNumber):
			n = 1
		x = x + 1
	x = 0

i = 0
while i < len(relationshipSourceAPRefs)-1:
	relationshipAP = Relationship(
		relationship_type= "next",
		source_ref= relationshipSourceAPRefs[i],
		target_ref= relationshipSourceAPRefs[i+1],
		description= "description"
	)
	f = open("APTModelGenerated.json", "a")
	if i < len(attackPatternPhaseNumber) - 2:
		print (relationshipAP, ',', file=f)
	else:
		print (relationshipAP, file=f)
	f.close()
	i = i + 1

#########################################################################################

#Close bundle
f = open("APTModelGenerated.json", "a")
print (']', file= f)
print ('}', file= f)
f.close()
