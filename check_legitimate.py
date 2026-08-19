import pandas as pd

df = pd.read_csv("consolidated_regulatory_technical_protected.csv")

legit = df[df["prompt_type"] == "legitimate"]
print(f"Total filas legitimate en este CSV: {len(legit)}")
print()
print(legit[["timestamp", "run_id", "was_blocked", "block_reason", "grounding_ratio"]].to_string())

print()
print("=== run_ids presentes en el archivo completo ===")
print(df["run_id"].value_counts())
