import pandas as pd
import lightgbm as lgb
import ipaddress
import hashlib
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

#Load the dataset
normal_data = pd.read_csv(r'D:\\IDS\\ML-powered-IDS-1\\preprocessed_Normal_Data.csv', index_col=0)
malicious_data = pd.read_csv(r'D:\\IDS\\ML-powered-IDS-1\\preprocessed_Malicious_Data.csv', index_col=0)

data = pd.concat([normal_data, malicious_data], axis=0)

#shuffle the dataset
data = data.sample(frac=1, random_state=42).reset_index(drop=True)

#preprocess the data
X= data.drop("label", axis=1)
y = data["label"]

def ip_to_int(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except ValueError:
        return 0 #to handle missing or invalid IPs

X['Source'] = X['Source'].apply(ip_to_int)
X['Destination'] = X['Destination'].apply(ip_to_int)

X['Source'] = pd.to_numeric(X['Source'], errors='coerce')
X['Source'] = X['Source'].fillna(-1).astype(int)

X['Destination'] = pd.to_numeric(X['Destination'], errors='coerce')
X['Destination'] = X['Destination'].fillna(-1).astype(int)

X = X.drop(columns="Info")

X = X.apply(pd.to_numeric, errors='coerce').fillna(-1)

#split the data into training and testing set
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

X_train = X_train.drop(columns=['Source'])
X_test = X_test.drop(columns=['Source'])


#initialize and begin the training
train_data = lgb.Dataset(X_train, label=y_train)
test_data = lgb.Dataset(X_test, label=y_test, reference=train_data)

#set parameters
params = {
    'objective': 'binary',
    'metric': 'binary_error',
    'boosting_type': 'gbdt', #Gradient Boosting Decision Tree
    'num_leaves': 31,
    'learning_rate': 0.05,
    'feature_fraction': 0.9
}

#train the model
gbm = lgb.train(params, train_data, valid_sets=[test_data], num_boost_round=100)

#Prediction and evaluation
y_pred = gbm.predict(X_test)
y_pred_binary = (y_pred > 0.5).astype(int)

print(f'Accuracy: {accuracy_score(y_test, y_pred_binary)}')

#print(gbm.feature_importance())
#print(X_train.columns)

#print(malicious_data.dtypes)
#print(malicious_data.iloc[:, 2].unique())

def hash_ip(ip):
    ip = str(ip)
    return int(hashlib.md5(ip.encode()).hexdigest(), 16) % (10 ** 8)

malicious_data['Source'] = malicious_data['Source'].apply(hash_ip)