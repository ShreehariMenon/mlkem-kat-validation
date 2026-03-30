import json, urllib.request, os

BASE_URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/"

def fetch_json(endpoint):
    url = f"{BASE_URL}{endpoint}"
    print(f"Fetching {url}...")
    try:
        req = urllib.request.urlopen(url)
        return json.loads(req.read().decode('utf-8'))
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

def inspect():
    kg_prompt = fetch_json("ML-KEM-keyGen-FIPS203/prompt.json")
    if kg_prompt:
        for tg in kg_prompt.get("testGroups", [])[:1]:
            print("KeyGen prompt keys:", tg.keys())
            print("KeyGen test[0] keys:", tg["tests"][0].keys())

    ed_prompt = fetch_json("ML-KEM-encapDecap-FIPS203/prompt.json")
    if ed_prompt:
        for tg in ed_prompt.get("testGroups", [])[:1]:
            print("Encap prompt keys:", tg.keys())
            print("Encap paramSet:", tg.get("parameterSet"))
            print("Encap func:", tg.get("function"))
            print("Encap test[0] keys:", tg["tests"][0].keys())

if __name__ == "__main__":
    inspect()
