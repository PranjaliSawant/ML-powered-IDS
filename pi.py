import pandas as pd
import joblib
import ipaddress
# from sklearn.preprocessing import MinMaxScaler, LabelEncoder

#Load the dataset
normal_data = pd.read_csv(r'D:\\IDS\\ML-powered-IDS-1\\preprocessed_Normal_Data.csv', index_col=0)
malicious_data = pd.read_csv(r'D:\\IDS\\ML-powered-IDS-1\\preprocessed_Malicious_Data.csv', index_col=0)

data = pd.concat([normal_data, malicious_data], axis=0)

# numerical_columns_01 = ['Time','Source','Length']
# numerical_columns_02 = ['No.','Time','Length']

# scaler = MinMaxScaler() #to initialize the MinMaxScaler

# #normal_data[numerical_columns_01] = scaler.fit_transform(normal_data[numerical_columns_01])
# #malicious_data[numerical_columns_02] = scaler.fit_transform(malicious_data[numerical_columns_02])
# scaler.fit(normal_data[numerical_columns_01])


#shuffle the dataset
data = data.sample(frac=1, random_state=42).reset_index(drop=True)

#preprocess the data
X= data.drop("label", axis=1)
y = data["label"]

def ip_to_int(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError:
        try:
            return int(ipaddress.IPv6Address(ip))
        except ipaddress.AddressValueError:
            return None

X['Source'] = X['Source'].apply(ip_to_int)
X['Destination'] = X['Destination'].apply(ip_to_int)

X = X.drop(columns="Info")
X = X.drop(columns="Source")

#split the data into training and testing set
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
X_test = X
y_test = y

#load the models
model_catboost = joblib.load(r'catBoost_model.pkl')
model_rf = joblib.load(r'Random_Forest_Model.pkl')

result1 = model_catboost.predict(X_test)
# result2 = model_rf.predict(X_test)

print(result1)
# print(result2)
# print(scaler.inverse_transform([result1]))
