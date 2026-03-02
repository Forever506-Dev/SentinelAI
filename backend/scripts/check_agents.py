import requests

r = requests.post('http://localhost:8080/api/v1/auth/login', json={'username':'admin','password':'Admin123!'})
token = r.json()['access_token']

# Check decommissioned agents
agents = requests.get('http://localhost:8080/api/v1/agents?status=decommissioned', 
                       headers={'Authorization': f'Bearer {token}'})
data = agents.json()
print(f"Decommissioned agents: {data.get('total', 0)}")
for a in data.get('agents', []):
    aid = a['id'][:8]
    print(f"  {aid} status={a['status']} hostname={a['hostname']}")

# Default list (no filter) should show 0 since we decommissioned
agents2 = requests.get('http://localhost:8080/api/v1/agents', 
                        headers={'Authorization': f'Bearer {token}'})
data2 = agents2.json()
print(f"\nVisible agents (default): {data2.get('total', 0)}")
