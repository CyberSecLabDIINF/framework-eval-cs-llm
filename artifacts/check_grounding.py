import pandas as pd

df = pd.read_csv("consolidated_regulatory_technical_protected.csv")

df["blocked_before_generation"] = df["was_blocked"] == 1

print("=== Cruce grounding_ratio nulo x was_blocked ===")
tabla = pd.crosstab(
    df["grounding_ratio"].isna(),
    df["blocked_before_generation"],
    rownames=["grounding_ratio_nulo"],
    colnames=["was_blocked"],
)
print(tabla)
print()

print("=== Cruce por prompt_type ===")
print(pd.crosstab(df["grounding_ratio"].isna(), df["prompt_type"]))
print()

no_blocked = df[df["was_blocked"] == 0]
print("=== De las NO bloqueadas, cuántas tienen grounding_ratio nulo ===")
print(f"Total no bloqueadas: {len(no_blocked)}")
print(f"De esas, grounding_ratio nulo: {no_blocked['grounding_ratio'].isna().sum()}")
