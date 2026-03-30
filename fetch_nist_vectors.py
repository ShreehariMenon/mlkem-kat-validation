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

def main():
    variants = {"ML-KEM-512": "mlkem512", "ML-KEM-768": "mlkem768", "ML-KEM-1024": "mlkem1024"}
    
    kg_prompt = fetch_json("ML-KEM-keyGen-FIPS203/prompt.json")
    kg_expect = fetch_json("ML-KEM-keyGen-FIPS203/expectedResults.json")
    
    ed_prompt = fetch_json("ML-KEM-encapDecap-FIPS203/prompt.json")
    ed_expect = fetch_json("ML-KEM-encapDecap-FIPS203/expectedResults.json")
    
    if not all([kg_prompt, kg_expect, ed_prompt, ed_expect]):
        print("Failed to download all JSONs")
        return

    os.makedirs("vectors/nist", exist_ok=True)
    
    for param_set, prefix in variants.items():
        rsp_path = f"vectors/nist/{prefix}_acvp.rsp"
        print(f"Generating {rsp_path}...")
        
        kg_inputs = {}
        for tg in kg_prompt.get("testGroups", []):
            if tg["parameterSet"] == param_set:
                for t in tg["tests"]:
                    kg_inputs[t["tcId"]] = t
                    
        kg_outputs = {}
        for tg in kg_expect.get("testGroups", []):
            for t in tg["tests"]:
                if t["tcId"] in kg_inputs:
                    kg_outputs[t["tcId"]] = t

        ed_inputs = {}
        ed_outputs = {}
        for tg in ed_prompt.get("testGroups", []):
            if tg["parameterSet"] == param_set and tg["function"] == "encapsulation":
                for t in tg["tests"]:
                    ed_inputs[t["tcId"]] = t
        for tg in ed_expect.get("testGroups", []):
            for t in tg["tests"]:
                if t["tcId"] in ed_inputs:
                    ed_outputs[t["tcId"]] = t
                    
        with open(rsp_path, "w") as f:
            f.write(f"# Official NIST ACVP Test Vectors for {param_set}\n\n")
            
            f.write("# === KEY GENERATION ===\n")
            # Limit to 25 to save time/space
            for tcId in list(kg_inputs.keys())[:25]:
                i = kg_inputs[tcId]
                o = kg_outputs[tcId]
                f.write(f"count = {tcId}\n")
                f.write(f"d = {i['d']}\n")
                f.write(f"z = {i['z']}\n")
                f.write(f"ek = {o['ek']}\n")
                f.write(f"dk = {o['dk']}\n\n")
                
            f.write("# === ENCAPSULATION ===\n")
            for tcId in list(ed_inputs.keys())[:25]:
                i = ed_inputs[tcId]
                o = ed_outputs[tcId]
                f.write(f"count = {tcId}\n")
                f.write(f"ek = {i['ek']}\n")
                if 'm' in i:
                    f.write(f"m = {i['m']}\n")
                elif 'msg' in i:
                    f.write(f"m = {i['msg']}\n")
                
                if 'c' in o:
                    f.write(f"ct = {o['c']}\n")
                elif 'ct' in o:
                    f.write(f"ct = {o['ct']}\n")
                    
                if 'k' in o:
                    f.write(f"ss = {o['k']}\n")
                elif 'ss' in o:
                    f.write(f"ss = {o['ss']}\n")
                f.write("\n")
                
if __name__ == "__main__":
    main()
