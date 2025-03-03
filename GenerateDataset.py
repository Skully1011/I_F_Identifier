import json
import pandas as pd
import glob
#import floss

IFILE = r"C:\Users\Chadwick\Source\Git\Research\DANGEROUS_MALWARE\analysis\Backdoor.Win32.Zepfod.aco-bdc9bf7f786d7b27d2230cba894fd09b31a36f7a5bf715ea9062a54f2e4246ae.json"
WORKDIR = r"C:\Users\Chadwick\Source\Git\Research\DANGEROUS_MALWARE\analysis"

def main():
    construct_dataset()
    #print(read_json(IFILE))
    return None

def construct_dataset():
    dataset = pd.DataFrame()
    # collect list of all PEframe reports
    report_paths = get_report_paths()
    # get feature list from all reports
    feature_list = construct_feature_list(report_paths)
    # construct a row by checking for each feature's occurence in the report
    # add the row to the overall dataset
    for report_path in report_paths:
        dataset.concat([dataset, create_row(report_path, feature_list)], ignore_index=True)
    dataset.to_hdf("000test_dataset.h5", key="block1_values", mode='w')

def construct_feature_list(report_paths) -> list:
    features = []
    for report_path in report_paths:
        report_data = read_json(report_path)
        report_features = extract_features(report_data)
    return features

def get_report_paths():
    return glob.glob(f"{WORKDIR}\\*.json")

def create_row(report_path:str, feature_list: list[str]):
    row = []
    report_data = read_json(report_path)
    report_features = extract_features(report_data)
    # first entry in every row is the count of sections in the PE
    row.append(report_features[0])
    # search for every feature in the aggregated feature_list in the current report
    for feature in feature_list[1:]:
        if feature in report_features:
        # feature is found in the report
            row.append(1)
        else:
        # feature not found in report
            row.append(0)
    return row

def extract_features(report_data):
    features = []
    features.append(report_data["peinfo"]["sections"]["count"])
    features.extend(report_data["peinfo"]["behavior"])
    features.extend(report_data["peinfo"]["breakpoint"])
    features.extend([dll for dll in report_data["peinfo"]["directories"]["import"]])
    # features.extend(fn_name for fn_name in report_data["peinfo"]["directories"]["import"])
    for dll in report_data["peinfo"]["directories"]["import"].keys:
        for fn_name in report_data["peinfo"]["directories"]["import"][dll]:
            features.append(report_data["peinfo"]["directories"]["import"][dll][fn_name])
    return features



def read_json(report_path) -> dict:
    with open(report_path, mode='r', encoding="utf-8") as report:
        report_data = json.load(report)
    return report_data

# def deobfuscate_strings(obfuscated_strings):
#     deobfuscated_strings = []
#     for string in obfuscated_strings:
#         if floss(string) != "":
#             deobfuscated_strings.append(floss(string))
#     print(deobfuscated_strings)
#     return deobfuscated_strings

if __name__ == "__main__":
    main()