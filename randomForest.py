import pandas as pd
import ipaddress
import joblib 
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import GridSearchCV

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
        return None #to handle missing or invalid IPs

X['Source'] = X['Source'].apply(ip_to_int)
X['Destination'] = X['Destination'].apply(ip_to_int)

X = X.drop(columns="Info")
X = X.drop(columns="Source")

#split the data into training and testing set
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

#initialize and train the model
rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1) #n_jobs is for speed, -1 is for maximum speed
rf_model.fit(X_train, y_train)

#predict the model
y_pred = rf_model.predict(X_test)

param_grid = {
    'n_estimators': [50, 100, 200],
    'max_depth': [None, 10, 20],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4]
}

#Initialize GridSearchCV
grid_search = GridSearchCV(estimator=rf_model, param_grid=param_grid, cv=3, n_jobs=-1, verbose=2)

grid_search.fit(X_train, y_train)

best_Parameters = grid_search.best_params_

#evaluation
#print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
#print("\nClassification Report:\n", classification_report(y_test, y_pred))
print("\nAccuracy:", accuracy_score(y_test, y_pred))

joblib.dump(best_Parameters, 'Random_Forest_Model.pkl')