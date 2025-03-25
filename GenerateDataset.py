import json
import pandas as pd
import glob
import logging
from pathlib import Path
#import floss

IFILE = r"C:\Users\Chadwick\Source\Git\Research\DANGEROUS_MALWARE\analysis\Backdoor.Win32.Zepfod.aco-bdc9bf7f786d7b27d2230cba894fd09b31a36f7a5bf715ea9062a54f2e4246ae.json"
WORKDIR = r"C:\Users\Chadwick\Source\Git\Research\DANGEROUS_MALWARE\analysis"
logger = logging.getLogger("datasetGenerator")

def main():
    logging.basicConfig(filename="datasetGenerator.log", level=logging.DEBUG)
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
        row = create_row(report_path, feature_list)
        if row is None:
            continue
        dataset = pd.concat([dataset, row], ignore_index=True)
    dataset.to_hdf("000test_dataset.h5", key="block1_values", mode='w')

def construct_feature_list(report_paths) -> list:
    features = []
    error_cnt = 0
    success_cnt = 0
    for report_path in report_paths:
        # some reports may have failed to generate from peframe
        # in this case the file is empty and the JSON decoder will throw an error
        # to continue processing simply skip processing this file for the dataset
        report_data = read_json(report_path)
        if report_data is None:
            error_cnt += 1
            continue
        report_features = extract_features(report_data)
        for report_feature in report_features:
            if report_feature not in features:
                features.append(report_feature)
        success_cnt += 1
        logger.info(f"Feature list: processed {Path(report_path).name} successfully.")
    logger.info(f"Finished building feature list. Processed {len(report_paths)} reports. Successfully extracted {success_cnt} reports. Failed to process {error_cnt} reports.")
    return features

def get_report_paths():
    return glob.glob(f"{WORKDIR}\\*.json")

def create_row(report_path:str, feature_list: list[str]):
    row = []
    report_data = read_json(report_path)
    if report_data is None:
        return None
    report_features = extract_features(report_data)
    # some reports are not empty but have no peinfo section
    if len(report_features) == 0:
        return None
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
    return  pd.DataFrame(row)

def extract_features(report_data) -> list:
    """
    Builds a list of features present in a given PEframe JSON report
    Used by construct_feature_list and create_row
    """
    features = []
    # guard statement, make sure peinfo is actually populated
    if len(report_data["peinfo"]) == 0:
        return []
    features.append(report_data["peinfo"]["sections"]["count"])
    features.extend(report_data["peinfo"]["behavior"])
    features.extend(report_data["peinfo"]["breakpoint"])
    features.extend([dll for dll in report_data["peinfo"]["directories"]["import"]])
    # features.extend(fn_name for fn_name in report_data["peinfo"]["directories"]["import"])
    for dll in report_data["peinfo"]["directories"]["import"].keys():
        for fn_entry in report_data["peinfo"]["directories"]["import"][dll]:
            #print(fn_entry["function"])
            features.extend(fn_entry["function"])
    return features



def read_json(report_path) -> dict:
    with open(report_path, mode='r', encoding="utf-8") as report:
        # could add a blacklist of filenames that are known bad reports to skip reading in the future...
        try:
            report_data = json.load(report)
        except json.JSONDecodeError as json_decode_err:
            logger.error(f"Could not process {Path(report_path).name}; {json_decode_err}")
            return None
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