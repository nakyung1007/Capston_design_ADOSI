import time, random, warnings, os
import pandas as pd
import numpy as np

import matplotlib.pyplot as plt
from matplotlib.pyplot import figure

from sklearn.metrics import accuracy_score
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn import preprocessing

warnings.filterwarnings("ignore")

# data = pd.read_json('packet_info.json').fillna(0)
# data.head()
# data.shape
# data.info()
# data.label.unique()
# data.label.value_counts()

class Model:
    def __init__(self, data, y):
        self.data = data
        self.y = y
        if not self.data.empty:
            X = preprocessing.StandardScaler().fit(self.data).transform(self.data)
            self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(X, self.y, random_state = 42, test_size = 0.3)
        else:
            print("데이터 프레임이 비어 있습니다.")
        self.RF = None
    
    def RandomForest(self):
        start_time = time.time()
        self.RF = RandomForestClassifier(criterion = 'gini', n_estimators = 500, min_samples_split = 10, max_features = 'sqrt', oob_score = True, random_state = 1, n_jobs =- 1).fit(self.X_train, self.y_train)
       
        predicted_rf = self.RF.predict(self.X_test)
        svm_accuracy = accuracy_score(self.y_test, predicted_rf)
        print(f"Accuracy of RF is : {round(svm_accuracy * 100, 2)}%", '\n')
        print("########################################################################")
        print(classification_report(predicted_rf, self.y_test))
        print("########################################################################")
        
        print(" = = %s seconds = = " % (time.time() - start_time))
        
    def predict(self, sample_data):
        new_data = preprocessing.StandardScaler().fit(self.data).transform(sample_data)

        predicted_labels = self.RF.predict(new_data)

        return predicted_labels

# print(data.head())
# print(os.getcwd())