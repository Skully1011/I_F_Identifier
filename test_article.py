##############################standard modules##################################
# misc. modules
import json
import logging
import pickle
import time
from multiprocessing import cpu_count

# processing
import numpy as np
import pandas as pd

# system operations
import os
os.environ["NUMEXPR_MAX_THREADS"]="272"
from pathlib import Path
import argparse

# ML
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import precision_recall_fscore_support, precision_score, recall_score, confusion_matrix
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelBinarizer

###############################local modules####################################
from Checking_Result import compute_result, time_data
from ThresholdRandomForest import ThresholdRandomForest

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
config_oc_path = "selected_param.json"
with open(config_oc_path) as f:
    CONFIG_OC = json.loads(f.read())


def test_oc(apt_df, malware_df, folder) -> None:
    logging.info("One class test - output in " + str(folder))
    apt_list = list(set(apt_df['apt']))
    clf = LinearDiscriminantAnalysis(solver='svd', )
    lda_time_list = []
    logging.info("LDA Phase")
    # Data preprocessing using LDA?
    for i in range(0, 10):
        lda_start_time = time.time()
        # create sub df from apt_df
        # drop the apt and md5 columns from the df
        # fit transform the df using LDA to standardize input data
        X_LDA = pd.DataFrame(clf.fit_transform(apt_df.drop(["apt", "md5"], axis=1), apt_df["apt"]))
        lda_end_train_time = time.time()
        lda_end_time = lda_end_train_time - lda_start_time
        lda_time_list.append(lda_end_time)
    # use fit transformed data for training
    X_LDA = pd.DataFrame(clf.fit_transform(apt_df.drop(["apt", "md5"], axis=1), apt_df["apt"]))
    X_LDA = X_LDA.add_prefix('col_')
    features_list = X_LDA.columns.values
    df = X_LDA.assign(apt=apt_df["apt"])
    logging.info("Binarizing Label Phase")
    lb = LabelBinarizer(neg_label=-1)
    classes = lb.fit_transform(df["apt"])
    binarized_class = pd.DataFrame(classes, columns=lb.classes_)
    apt_binarized = pd.concat([df, binarized_class], axis=1, sort=False).assign(apt=apt_df["apt"]).reset_index(
        drop=True)

    # noAPT_LDA = pd.DataFrame(clf.transform(malware_df.drop(["md5"], axis=1))).add_prefix("col_")
    noAPT_LDA = pd.DataFrame(clf.transform(malware_df.drop(["apt", "md5"], axis=1)))
    kf = StratifiedKFold(n_splits=10, random_state=1, shuffle=True)
    model_list = []
    time_data = pd.DataFrame(columns=["apt_name","train","test_apt", "test_malware"])
    prediction_list = []
    result_list = []
    logging.info("Test Beginning")
    for train_index, test_index in kf.split(apt_binarized, apt_df["apt"]):
        X = apt_binarized[features_list]
        y = apt_binarized[apt_list]
        pred_df = pd.DataFrame(columns=apt_list)
        res_df = pd.DataFrame(columns=apt_list)
        current_model_dict = dict()
        current_pred_dict = dict()
        for apt_name in apt_list:
            # logging.info("Testing "+apt_name)
            start_time = time.time()
            y_train = y[apt_name].iloc[train_index]
            y_test = y[apt_name].iloc[test_index]
            apt_pred_dict = dict()
            apt_pred_dict["apt"] = y_test
            X_train = X.iloc[train_index][y_train == 1]
            X_test = X.iloc[test_index]
            current_contamination = CONFIG_OC[apt_name][0]
            clf = IsolationForest(contamination=current_contamination, n_estimators=CONFIG_OC[apt_name][1],
                                  random_state=42,
                                  n_jobs=cpu_count() - 1)
            clf.fit(X_train, y_train[y_train == 1])
            end_train_time = time.time()
            end_train = end_train_time - start_time
            current_model_dict[apt_name] = clf
            pred_apt = clf.predict(X_test)

            apt_pred_dict["pred_apt"] = pred_apt
            end_test_apt_time = time.time()
            end_test_apt = end_test_apt_time - end_train_time
            pred_malware = clf.predict(noAPT_LDA)
            apt_pred_dict["pred_malware"] = pred_malware
            pred_df[apt_name] = np.append(pred_apt, pred_malware)
            res_df[apt_name] = np.append(y_test,[-1] * len(pred_malware))
            current_pred_dict[apt_name] = apt_pred_dict
            end_test_malware_time = time.time()
            end_test_malware = end_test_malware_time - end_test_apt_time
            time_data = pd.concat([time_data, pd.DataFrame({"apt_name":[apt_name],"train":[end_train],"test_apt":[end_test_apt], "test_malware":[end_test_malware]})], ignore_index=True)

        model_list.append(current_model_dict)
        prediction_list.append(current_pred_dict)
        result_list.append({"pred": pred_df, "res": res_df})

    output_dict = {"models":model_list, "pred":prediction_list, "lda_time":lda_time_list, "time_data":time_data}

    logging.info("Store result")
    with open(folder+"oc_result.p","wb") as outfile:
        pickle.dump(output_dict, outfile)

    with open(folder+"oc_result_clean.p","wb") as outfile:
        pickle.dump(result_list, outfile)
    logging.info("One class test completed")

def check_parameters(apt_df) -> None:
    apt_list = list(set(apt_df['apt']))
    clf = LinearDiscriminantAnalysis(solver='svd')
    logging.info("LDA Phase")
    X_LDA = pd.DataFrame(clf.fit_transform(apt_df.drop(["apt", "md5"], axis=1), apt_df['apt']))
    X_LDA = X_LDA.add_prefix('col_')
    features_list = X_LDA.columns.values
    df = X_LDA.assign(apt=apt_df["apt"])
    logging.info("Binarizing Label Phase")
    lb = LabelBinarizer(neg_label=-1)
    classes = lb.fit_transform(df["apt"])
    binarized_class = pd.DataFrame(classes, columns=lb.classes_)
    apt_binarized = pd.concat([df, binarized_class], axis=1, sort=False).assign(apt=apt_df["apt"]).reset_index(
        drop=True)
    kf = StratifiedKFold(n_splits=10, random_state=1, shuffle=True)
    logging.info("Test Beginning")

    result = dict()
    for apt_name in apt_list:
        print(apt_name)
        apt_list = []
        X = apt_binarized[features_list]
        y = apt_binarized[apt_name]
        for current_contamination in [x/100 for x in list(range(0,30,1))]:
            for current_estimator in range(50,250,50):
                y_pred_total = []
                y_train_total = []
                for train_index, test_index in kf.split(X, y):
                    y_train = y.iloc[train_index]
                    y_true = y.iloc[test_index]
                    X_train = X.iloc[train_index][y_train==1]
                    X_test = X.iloc[test_index]
                    clf = IsolationForest(random_state=42, n_jobs=cpu_count()-1, behaviour='new', contamination=current_contamination, n_estimators=current_estimator)
                    clf.fit(X_train, y_train[y_train==1])
                    y_pred = clf.predict(X_test)
                    for elem in y_pred:
                        y_pred_total.append(elem)
                    for elem in y_true:
                        y_train_total.append(elem)
                precision = precision_score(y_train_total, y_pred_total)
                recall = recall_score(y_train_total, y_pred_total)
                cm = confusion_matrix(y_train_total, y_pred_total)
                tn, fp, fn, tp = cm.ravel()
                apt_dict = {"contamination":current_contamination, "n_estimators":current_estimator, "precision":precision,"recall":recall, "tn":int(tn), "fp":int(fp),"fn":int(fn), "tp":int(tp)}
                apt_list.append(apt_dict)
        result[apt_name] = apt_list
    with open("parameter_selection.json","w") as outfile:
        json.dump(result, outfile)
    print(result)


def test_rf(apt_df, malware_df, folder) -> None:
    logging.info("ThresholdRandomForest test - output in " + str(folder))
    # DEBUG
    malware_df
    malware_df.loc["apt"] = ""
    # DEBUG
    malware_df
    X = apt_df.drop(["apt"], axis=1)
    y = apt_df['apt']
    logging.info("Binarizing Label Phase")
    lb = LabelBinarizer(neg_label=-1)
    classes = lb.fit_transform(y)
    binarized_class = pd.DataFrame(classes, columns=lb.classes_)
    df_binarized = pd.concat([apt_df, binarized_class], axis=1, sort=False)

    kf = StratifiedKFold(n_splits=10, random_state=1, shuffle=True)
    pred_5_list = []
    pred_10_list = []
    pred_15_list = []
    time_train_list = []
    time_apt_list = []
    logging.info("Test Beginning")
    for train_index, test_index in kf.split(X, y):
        start_time = time.time()
        y_train, y_test = y.iloc[train_index].reset_index(drop=True), pd.concat([y.iloc[test_index],
            malware_df["apt"]], ignore_index=True).reset_index(drop=True)
        X_train, X_test = X.iloc[train_index].reset_index(drop=True), pd.concat([X.iloc[test_index],
            malware_df.drop("apt", axis=1)], ignore_index=True).reset_index(drop=True)
        clf = ThresholdRandomForest(percentage=0.05, n_estimators=150, random_state=42,
                                    n_jobs=cpu_count() - 1, class_name="apt")
        clf.fit(X_train, y_train)
        end_train_time = time.time()
        end_train = end_train_time - start_time
        time_train_list.append(end_train)
        clf.set_percentage(0.05)
        pred = clf.predict(X_test)
        pred_5_list.append(pred)
        end_test = time.time() - end_train_time
        time_apt_list.append(end_test)
        clf.set_percentage(0.10)
        pred = clf.predict(X_test)
        pred_10_list.append(pred)
        clf.set_percentage(0.15)
        pred = clf.predict(X_test)
        pred_15_list.append(pred)
    result_dict = {"pred_5": pred_5_list, "pred_10": pred_10_list, "pred_15": pred_15_list,
                   "time_apt": time_apt_list, "time_train": time_train_list, "df_binarized": df_binarized}

    logging.info("Store result")
    with open(folder+"rf_result.p", "wb") as outputfile:
        pickle.dump(result_dict, outputfile)
    logging.info("One class test completed")


def compute_best_six(apt_df) -> list:
    X = apt_df.drop(["md5","apt"], axis=1)
    y = apt_df['apt']
    y_true = []
    y_pred = []
    kf = StratifiedKFold(n_splits=10, random_state=1, shuffle=True)
    logging.info("Checking best six classes")
    imp_feat = []
    for train_index, test_index in kf.split(X, y):
        y_train = y.iloc[train_index]
        y_test = y.iloc[test_index]
        X_train = X.iloc[train_index]
        X_test = X.iloc[test_index]
        clf = RandomForestClassifier(n_estimators=150, random_state=1, n_jobs=cpu_count() - 1)
        clf.fit(X_train, y_train)
        pred = clf.predict(X_test)
        y_true.extend(y_test)
        y_pred.extend(pred)
        feature_importances = pd.DataFrame(clf.feature_importances_,
                                           index=X_train.columns,
                                           columns=['importance']).sort_values('importance', ascending=False)
        imp_feat.append(feature_importances[feature_importances["importance"]>0])
    # print(imp_feat)
    metrics_summary = precision_recall_fscore_support(
        y_true=y_true,
        y_pred=y_pred, labels=clf.classes_)
    metrics_sum_index = ['precision', 'recall', 'f1-score', 'support']
    class_report_df = pd.DataFrame(
        list(metrics_summary),
        index=metrics_sum_index, columns=clf.classes_).transpose().sort_values(["precision", "recall"], ascending=[0, 0])

    # print(class_report_df)
    # logging.info("Started Analysis with 0.95")
    # best_six = list(class_report_df.iloc[0:6].index)
    best_six = list(class_report_df[(class_report_df["precision"] > 0.95) & (class_report_df["recall"] > 0.95)].index)
    return best_six

def load_data_file(filename: str) -> pd.DataFrame:
    """
    Simple function for reading in datasets.
    May be expanded to support more formats, but currently just CSV and H5/HDF
    """
    # for splitting filenames and file extensions
    ext = Path(filename).suffix
    stem = Path(filename).stem
    if ext == "":
        exit("Unrecognized data file type; No extension provided.")

    # read in file; special handling for CSV since the model is designed to use h5
    if ".csv" in ext:
        df = pd.read_csv(filename)
        new_filename = f"{stem}.h5"
        df.to_hdf(new_filename, key=f"{stem}", mode='w', format="table")
        df = pd.read_hdf(f"{new_filename}")
    elif ".h5" in ext or ".hdf" in ext:
        df = pd.read_hdf(filename)
    else:
        exit("Unsupported data file type; Must be CSV or H5/HDF.")
    return df

def build_parser() -> argparse.ArgumentParser:
    """
    Creates an parser for CLI arguments
    Current arguments include the APT and non-APT malware dataset files
    """
    parser = argparse.ArgumentParser(prog="AptMalwareIdentifier", description="ML model for identifying and attributing APT malware samples.")
    parser.add_argument("-a", "--aptfile", type=str, default="malware_apt.h5", help="The dataset of APT malware.", dest="malware_apt")
    parser.add_argument("-n", "--nonaptfile", type=str, default="malware_non_apt.h5", help="The dataset of non-APT malware.", dest="malware_non_apt")
    parser.add_argument("--columns", type=str, default="selected_columns.json", help="The JSON file of the selected column labels.", dest="selected_columns")
    parser.add_argument("--class", type=str, default="selected_class.json", help="The JSON file of the selected class.", dest="selected_class")
    return parser

def cli() -> tuple:
    """
    CLI used to gather dataset arguments
    """
    parser = build_parser()
    args = parser.parse_args()
    return args.malware_apt, args.malware_non_apt, args.selected_columns, args.selected_class

def main():
    # Get dataset arguments if supplied
    malware_apt, malware_non_apt, selected_columns, selected_class = cli()
    apt_df = load_data_file(malware_apt)
    malware_df = load_data_file(malware_non_apt)

    with open(selected_columns,"r") as infile:
        selected_columns = json.load(infile)

    with open(selected_class,"r") as infile:
        selected_class = json.load(infile)

    with open("selected_columns.json", "r") as infile:
        apt_selected_columns = json.load(infile)

    malware_df["apt"] = ""
    reduced_apt_df = apt_df[apt_selected_columns]
    reduced_malware_df = malware_df[selected_columns]
    folder = "test/"

    six_folder = folder + "6_classes/"
    if not os.path.exists(six_folder):
        os.makedirs(six_folder)
    test_rf(reduced_apt_df[reduced_apt_df["apt"].isin(selected_class)].reset_index(drop=True), reduced_malware_df, six_folder)
    test_oc(reduced_apt_df[reduced_apt_df["apt"].isin(selected_class)].reset_index(drop=True), reduced_malware_df, six_folder)
    compute_result(six_folder)
    time_data(six_folder)

    all_folder = folder + "all_classes/"
    if not os.path.exists(all_folder):
        os.makedirs(all_folder)
    test_rf(reduced_apt_df, reduced_malware_df, all_folder)
    test_oc(reduced_apt_df, reduced_malware_df, all_folder)
    compute_result(all_folder)
    time_data(all_folder)

main()