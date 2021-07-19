import sqlite3

from stix2 import AttackPattern
from stix2 import Campaign
from stix2 import Identity
from stix2 import Indicator
from stix2 import Infrastructure
from stix2 import IntrusionSet
from stix2 import Location
from stix2 import Malware
from stix2 import Report
from stix2 import Tool
from stix2 import Vulnerability
from stix2 import CourseOfAction

from stix2 import Bundle
from stix2 import Relationship
from stix2 import parse

#########################################################################################

apt = input("Enter APT name:")
n = 0
i = 0

intrusionSetId = []
intrusionSetName = []
intrusionSetDescription = []
aliases = []

attackPatternTypes = []
attackPatternId = []
attackPatternCreated = []
attackPatternModified = []
attackPatternNames = []
attackPatternDescriptions = []
attackPatternPhaseNames = []

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

courseOfActionTypes = []
courseOfActionId = []
courseOfActionTarget = []
courseOfActionCreated = []
courseOfActionModified = []
courseOfActionNames = []
courseOfActionDescriptions = []
courseOfActionRelation =[]

indicatorTypes = []
indicatorId = []
indicatorAPId = []
indicatorNames = []
indicatorDescriptions = []
indicatorIndicatorsType = []
indicatorPhaseNames = []
indicatorCommand = []
indicatorTarget = []

relationshipType = []
relationshipSourceRefs = []
relationshipTargetRefs = []
relationshipDescriptions = []

relationshipCoA_APType = []
relationshipSourceCoA_APRefs = []
relationshipTargetCoA_APRefs = []
relationshipCoA_APDescriptions = []

relationshipMT_APType = []
relationshipSourceMT_APRefs = []
relationshipTargetMT_APRefs = []
relationshipMT_APDescriptions = []

#########################################################################################

#Open bundle 
db_file = "C:/Users/oscar/ATTACK-Tools-master/attack_view_db.sqlite" # path to the local db file 
conn = None

try:
    conn = sqlite3.connect(db_file)
except Error as e:
    print (e)

f = open(str(apt) + ".json", "w")
print ('{', file= f)
print ('"type": "bundle",', file= f)
print ('"id": "bundle--f7cdadd5-24c2-49ee-afbc-a807d33dc5dd",', file= f)
print ('"objects": [', file= f)
f.close()

#########################################################################################

#Intrusion-set
intrusionSetCur = conn.cursor()
intrusionSetCur.execute("SELECT fk_object_id, alias, so.description FROM aliases INNER JOIN sdos_object so ON aliases.fk_object_id = so.id WHERE aliases.alias = ?", (str(apt),))
intrusionSetRows = intrusionSetCur.fetchall()

for row in intrusionSetRows:
	while row[0] not in intrusionSetId:
		intrusionSetId.append(row[0])
		intrusionSetName.append(row[1])
		intrusionSetDescription.append(row[2])

aliasCur = conn.cursor()
aliasCur.execute("SELECT alias FROM aliases WHERE aliases.fk_object_id= ?", (intrusionSetId[0],))
aliasRows = aliasCur.fetchall()
for row in aliasRows:
	aliases.append(row[0])

while i < len(intrusionSetRows):
	intrusionSet = IntrusionSet(
		id= intrusionSetId[0],
		name= intrusionSetName[0],
		aliases= aliases,
		description= intrusionSetDescription[0],
		primary_motivation="espionage, organizational-gain"
	)
	f = open(str(apt) + ".json", "a")
	print (intrusionSet, ',', file=f)
	f.close()
	i = i + 1

#########################################################################################

#Attack-patterns
attackPatternCur = conn.cursor()
attackPatternCur .execute("SELECT type, kcp.fk_object_id, created, modified, sdos_object.name, sdos_object.description, phase_name FROM sdos_object INNER JOIN relationship r on sdos_object.id = r.target_ref INNER JOIN kill_chain_phases kcp on sdos_object.id = kcp.fk_object_id WHERE r.source_ref = ? AND target_ref LIKE '%attack-pattern%' GROUP BY target_ref", (intrusionSetId[0],))
attackPatternRows = attackPatternCur .fetchall()

for row in attackPatternRows:
	while row[1] not in attackPatternId:
		attackPatternTypes.append(row[0])
		attackPatternId.append(row[1])
		attackPatternCreated.append(row[2])
		attackPatternModified.append(row[3])
		attackPatternNames.append(row[4])
		attackPatternDescriptions.append(row[5])
		attackPatternPhaseNames.append(row[6])

i = 0
while i < len(attackPatternId):
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
	f = open(str(apt) + ".json", "a")
	if i < len(attackPatternId) - 1:
		print (attackPattern, ',', file=f)
	f.close()
	i = i + 1

#########################################################################################

#Malware
malwareCur = conn.cursor()
malwareCur.execute("SELECT type, sdos_object.id, created, modified, sdos_object.name, sdos_object.description FROM sdos_object INNER JOIN relationship r on sdos_object.id = r.target_ref WHERE r.source_ref = ? AND target_ref LIKE '%malware%' GROUP BY target_ref", (intrusionSetId[0],))
malwareRows = malwareCur.fetchall()

for row in malwareRows:
	while row[1] not in malwareId:
		malwareTypes.append(row[0])
		malwareId.append(row[1])
		malwareCreated.append(row[2])
		malwareModified.append(row[3])
		malwareNames.append(row[4])
		malwareDescriptions.append(row[5])

i = 0
while i < len(malwareId):
	malware = Malware(
		id= malwareId[i],
		created= malwareCreated[i],
		modified= malwareModified[i],
		name= malwareNames[i],
		description= malwareDescriptions[i],
		is_family= False
	)
	f = open(str(apt) + ".json", "a")
	if i < len(malwareId):
		print (malware, ',', file=f)
	f.close()
	i = i + 1

#########################################################################################

#Tool
toolCur = conn.cursor()
toolCur.execute("SELECT type, sdos_object.id, created, modified, sdos_object.name, sdos_object.description FROM sdos_object INNER JOIN relationship r on sdos_object.id = r.target_ref WHERE r.source_ref = ? AND target_ref LIKE '%tool%' GROUP BY target_ref", (intrusionSetId[0],))
toolRows = toolCur.fetchall()

for row in toolRows:
	while row[1] not in toolId:
		toolTypes.append(row[0])
		toolId.append(row[1])
		toolCreated.append(row[2])
		toolModified.append(row[3])
		toolNames.append(row[4])
		toolDescriptions.append(row[5])

i = 0
while i < len(toolId):
	tool = Tool(
		id= toolId[i],
		created= toolCreated[i],
		modified= toolModified[i],
		name= toolNames[i],
		description= toolDescriptions[i]
	)
	f = open(str(apt) + ".json", "a")
	if i < len(toolId):
		print (tool, ',', file=f)
	f.close()
	i = i + 1

#########################################################################################

#Course Of Action
courseOfActionCur = conn.cursor()
courseOfActionCur.execute("SELECT relationship_type, source_ref, target_ref, created, modified, sdos_object.name ,r.description, relationship_type FROM sdos_object INNER JOIN relationship r on sdos_object.id = r.target_ref WHERE r.source_ref LIKE '%course-of-action%' AND  r.target_ref IS (SELECT rr.target_ref FROM relationship rr WHERE rr.source_ref = ? GROUP BY target_ref)", (intrusionSetId[0],))
courseOfActionRows = courseOfActionCur.fetchall()

for row in courseOfActionRows:
	while row[1] not in courseOfActionId:
		courseOfActionTypes.append(row[0])
		courseOfActionId.append(row[1])
		courseOfActionTarget.append(row[2])
		courseOfActionCreated.append(row[3])
		courseOfActionModified.append(row[4])
		courseOfActionNames.append(row[5])
		courseOfActionDescriptions.append(row[6])
		courseOfActionRelation.append(row[7])

i = 0
while i < len(courseOfActionRows):
	courseOfAction = CourseOfAction(
		id= courseOfActionId[i],
		created= courseOfActionCreated[i],
		modified= courseOfActionModified[i],
		name= courseOfActionNames[i],
		description= courseOfActionDescriptions[i]
	)
	f = open(str(apt) + ".json", "a")
	if i < len(courseOfActionRows):
		print (courseOfAction, ',', file=f)
	f.close()
	i = i + 1

#########################################################################################

#Indicator
indicatorCur = conn.cursor()
indicatorCur.execute("SELECT aa.fk_attack_id, aa.display_name, aat.description, phase_name, aat.executor_command, aa.id FROM sdos_object INNER JOIN relationship r on sdos_object.id = r.target_ref INNER JOIN kill_chain_phases kcp on sdos_object.id = kcp.fk_object_id INNER JOIN atomic_attack aa ON kcp.fk_object_id = aa.fk_attack_id INNER JOIN atomic_attack_test aat on aa.id = aat.fk_atomic_attack_id WHERE r.source_ref = ? GROUP BY aat.name", (intrusionSetId[0],))
indicatorRows = indicatorCur.fetchall()

for row in indicatorRows:
	indicatorAPId.append(row[0])
	indicatorNames.append(row[1])
	indicatorDescriptions.append(row[2])
	indicatorPhaseNames.append(row[3])
	indicatorCommand.append(row[4])
	indicatorTarget.append(row[5])

i = 0
while i < len(indicatorRows):
	indicator = Indicator(
		name= indicatorNames[i],
		description= indicatorDescriptions[i],
		indicator_types= ["malicious-activity"],
		pattern= "[file:name ='' OR ipv4-addr:value ='']",
		pattern_type="stix",
		kill_chain_phases= [
	        {
	            "kill_chain_name": "mandiant-attack-lifecycle-model",
	            "phase_name": indicatorPhaseNames[i]
	        }
	    ]
	)
	indicatorId.append(indicator.id)
	f = open(str(apt) + ".json", "a")
	if i < len(indicatorRows):
		print (indicator, ',', file=f)
	f.close()
	i = i + 1

#########################################################################################

#Relatioships
#Malware & Tool | Attack-pattern relationship
mt_ap = malwareId + toolId

mt_apCur = conn.cursor()
mt_apQuery = 'SELECT relationship_type, source_ref, target_ref, relationship.description, so.name, so.description FROM relationship INNER JOIN sdos_object so on relationship.target_ref = so.id WHERE '
while n < len(mt_ap):
	if (n < len(mt_ap) - 1):
		mt_apQuery = mt_apQuery + 'relationship.source_ref IS ' + "'" + (mt_ap[n]) + "'" + " AND target_ref LIKE '%attack-pattern%' OR "
	else:
		mt_apQuery = mt_apQuery + 'relationship.source_ref IS ' + "'" + (mt_ap[n]) + "'" + " AND target_ref LIKE '%attack-pattern%' "
	n = n + 1
mt_apQuery = mt_apQuery + 'GROUP BY target_ref;'
mt_apCur.execute(mt_apQuery)
mt_apRows = mt_apCur.fetchall()

for row in mt_apRows:
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
	f = open(str(apt) + ".json", "a")
	if i < len(mt_apRows):
		print (relationshipMT_AP, ',', file=f)
	f.close()
	i = i + 1

#Indicator | Attack-pattern relationship
i = 0
while i < len(indicatorRows):
	relationshipI_AP = Relationship(
		relationship_type= "indicates",
		source_ref= indicatorId[i],
		target_ref= indicatorAPId[i],
		description= indicatorCommand[i]
	)
	f = open(str(apt) + ".json", "a")
	if i < len(indicatorRows):
		print (relationshipI_AP, ',', file=f)
	f.close()
	i = i + 1

#Course-Of-Action | Attack-pattern relationship
i = 0
while i < len(courseOfActionRows):
	relationshipCoA_AP = Relationship(
		relationship_type= courseOfActionRelation[i],
		source_ref= courseOfActionId[i],
		target_ref= courseOfActionTarget[i],
		description= courseOfActionDescriptions[i]
	)
	f = open(str(apt) + ".json", "a")
	if i < len(courseOfActionRows):
		print (relationshipCoA_AP, ',', file=f)
	f.close()
	i = i + 1

#Intrusion-set | Attack-pattern & Malware & Tool relationship
relationshipCur = conn.cursor()
relationshipCur.execute("SELECT relationship_type, source_ref, target_ref, relationship.description, so.name, so.description FROM relationship INNER JOIN sdos_object so on relationship.target_ref = so.id     WHERE relationship.source_ref = ?     AND target_ref LIKE '%attack-patter%'    OR relationship.source_ref = ?    AND target_ref LIKE '%malware%'    OR relationship.source_ref = ?    AND target_ref LIKE '%tool%' GROUP BY target_ref", (intrusionSetId[0], intrusionSetId[0], intrusionSetId[0]))
relationshipRows = relationshipCur.fetchall()

for row in relationshipRows:
	relationshipType.append(row[0])
	relationshipSourceRefs.append(row[1])
	relationshipTargetRefs.append(row[2])
	relationshipDescriptions.append(row[3])

i = 0
while i < len(relationshipRows):
	relationship = Relationship(
		relationship_type= relationshipType[i],
		source_ref= relationshipSourceRefs[i],
		target_ref= relationshipTargetRefs[i],
		description= relationshipDescriptions[i]
	)
	f = open(str(apt) + ".json", "a")
	if i < len(relationshipRows)-1:
		print (relationship, ',', file=f)
	else:
		print (relationship, file=f)
	f.close()
	i = i + 1

#########################################################################################

#Close bundle
f = open(str(apt) + ".json", "a")
print (']', file= f)
print ('}', file= f)
f.close()