import pandas as pd
import glob

for path in sorted(glob.glob("consolidated_*.csv")):
    df = pd.read_csv(path)
    legit = df[df["prompt_type"] == "legitimate"]
    print(f"{path}: {len(legit)} filas legitimate")
    if len(legit) > 0:
        print(f"  run_ids: {legit['run_id'].unique()}")
        print(f"  timestamps: {legit['timestamp'].min()} a {legit['timestamp'].max()}")
    print()
