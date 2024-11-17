#DATA PREPROCESSING
import pandas as pd
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import ipaddress

normal_data = pd.read_csv(r'D:\\IDS\\ML-powered-IDS-1\\network-traffic-dataset\\Normal_data.csv', low_memory = False)
malicious_data = pd.read_csv(r'D:\\IDS\\ML-powered-IDS-1\\network-traffic-dataset\\Malicious_data.csv', low_memory = False)                          

normal_data['No.'] = pd.to_numeric(normal_data['No.'], errors='coerce')
normal_data['Time'] = pd.to_numeric(normal_data['Time'], errors='coerce')
normal_data['Source'] = pd.to_numeric(normal_data['Source'], errors='coerce')
normal_data['Length'] = pd.to_numeric(normal_data['Length'], errors='coerce')

malicious_data['No.'] = pd.to_numeric(malicious_data['No.'], errors='coerce')
malicious_data['Time'] = pd.to_numeric(malicious_data['Time'], errors='coerce')
malicious_data['Length'] = pd.to_numeric(malicious_data['Source'], errors='coerce')

# Now you can fill or handle NaN values as needed, for example, by replacing NaN with a default value:
normal_data.fillna(0, inplace=True)  # Replace NaN with 0 (or another strategy)
malicious_data.fillna(0, inplace=True)

#remove duplicates
normal_data.drop_duplicates(inplace=True)
malicious_data.drop_duplicates(inplace=True)

#Normalization
#We need to normalize the numerical coulmns separately, as they can be directly normalized

numerical_columns_01 = ['No.','Time','Source','Length']
numerical_columns_02 = ['No.','Time','Length']

scaler = MinMaxScaler() #to initialize the MinMaxScaler

normal_data[numerical_columns_01] = scaler.fit_transform(normal_data[numerical_columns_01])
malicious_data[numerical_columns_02] = scaler.fit_transform(malicious_data[numerical_columns_02])

#To normalize the protocol column which is categorical, we need to encode it to numeric value for ML models

normal_data['Protocol'] = normal_data['Protocol'].replace(0, 'Unidentified')
#malicious_data['Protocol'] = malicious_data['Protocol'].replace(0, 'Unidentified')

label_encoder = LabelEncoder() #initialize the encoder

#encode the target column
normal_data['Protocol'] = label_encoder.fit_transform(normal_data['Protocol'])

#For malicious data
#There are some IPv6 addresses too, they need to be converted to IPv4
def convert_ip_to_int(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError:
        try:
            return int(ipaddress.IPv6Address(ip))
        except ipaddress.AddressValueError:
            return None

malicious_data['Source'] = malicious_data['Source'].apply(convert_ip_to_int)
malicious_data['Protocol'] = malicious_data['Protocol'].apply(convert_ip_to_int)

#add a label column with value 0 and 1
normal_data['label'] = 0

malicious_data['label'] = 1

#saving the preprocessed datasets
normal_data.to_csv('preprocessed_Normal_Data.csv', index=False)
malicious_data.to_csv('preprocessed_Malicious_Data.csv', index=False)

