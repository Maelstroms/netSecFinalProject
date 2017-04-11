import json
dict = {'Name': 'Zara', 'Age': 7}


print dict
packet = json.dumps(dict)
packet2 = json.loads(packet)
print packet
print packet2

if(packet2['Name'] == dict['Name']) :
	print('true')
else :
	print('false')

print packet2['Name']
print dict['Name']
print packet2.keys()