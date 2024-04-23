import json
import csv

def main() -> None:
    """
    This is a small helper script to extract column labels out of a csv file and convert them into a json format
    """
    column_names = ""
    with open("./dataset/AndroidMalwareDetection/TUANDROMD.csv", encoding="utf-8") as csvf:
        csv_reader = csv.reader(csvf, delimiter=',')
        column_names = next(csv_reader)
    with open("tuandromd_selected_columns.json", "w", encoding="utf-8") as jsonf:
        json_str = json.dumps(column_names, separators=(",\r", ": "))
        jsonf.write(json_str)

if __name__ == "__main__":
    main()