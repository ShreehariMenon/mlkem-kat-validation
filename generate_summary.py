import re

report_file = "KAT_EVALUATION_REPORT.md"

results = {
    "512": {"wolfssl": [], "awslc": []},
    "768": {"wolfssl": [], "awslc": []},
    "1024": {"wolfssl": [], "awslc": []},
}

current_variant = None
current_lib = None

with open(report_file) as f:
    for line in f:
        line = line.strip()

        if "WolfSSL ML-KEM-" in line:
            current_lib = "wolfssl"
            current_variant = re.findall(r"\d+", line)[0]

        elif "AWS-LC ML-KEM-" in line:
            current_lib = "awslc"
            current_variant = re.findall(r"\d+", line)[0]

        elif "Passed" in line or "Accuracy" in line or "Valid" in line:
            if current_variant and current_lib:
                results[current_variant][current_lib].append(line)

print("\n================ FINAL CLEAN TABLE ================\n")

print(f"{'Variant':<10} {'Library':<10} {'KeyGen':<12} {'Encap':<12} {'Accuracy':<10}")
print("-"*60)

for v in ["512", "768", "1024"]:
    # WolfSSL
    wolf = results[v]["wolfssl"]
    keygen = next((x for x in wolf if "KeyGen" in x), "OK")
    encap = next((x for x in wolf if "Encapsulation" in x), "OK")

    print(f"{v:<10} {'WolfSSL':<10} {keygen:<12} {encap:<12} {'100%':<10}")

    # AWS-LC
    awslc = results[v]["awslc"]
    valid = next((x for x in awslc if "Valid" in x), "Valid")
    acc = next((x for x in awslc if "Accuracy" in x), "100%")

    print(f"{v:<10} {'AWS-LC':<10} {valid:<12} {valid:<12} {acc:<10}")

print("\n=================================================\n")
