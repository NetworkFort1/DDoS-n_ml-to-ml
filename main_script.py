import pandas as pd
import numpy as np
import pickle as pkl
import ipaddress
from ipaddress import ip_address
from elasticsearch import Elasticsearch
import subprocess
import warnings
# Suppress a specific warning
warnings.filterwarnings("ignore", message="Specific warning message")


path ='/opt/zeek/spool/zeek/conn.log'
try:
    # Load the model from disk
    try:
        filename = 'DDoS_Model.sav'
        loaded_model = pkl.load(open(filename, 'rb'))
    except Exception as e:
        raise Exception(e)

    # Load the Elasticsearch instance
    try:
        es = Elasticsearch("http://192.168.196.98:9200")
    except Exception as e:
        raise Exception(e)

    # Parse the log file
    with subprocess.Popen(['tail', '-f', path], stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as proc:
        for line in proc.stdout:
            line = line.rstrip('\n')
            if line and line[0] != '#':
                line = line.split('\t')
                ts = line[0]
                id_resp_p = line[5]
                proto = line[6]
                duration = line[8]
                missed_bytes = line[14]
                orig_pkts = line[16]
                orig_ip_bytes = line[17]

                df = pd.DataFrame({'id.resp_p': [id_resp_p], 'proto': [proto], 'duration': [duration], 'missed_bytes': [missed_bytes], 'orig_pkts': [orig_pkts], 'orig_ip_bytes': [orig_ip_bytes]})
                df_copy = df.copy()
                df_copy['ts'] = [ts]

                df['id.resp_p']=df['id.resp_p'].replace('-','0')
                df['id.resp_p'] =df['id.resp_p'].astype(int)
                df['duration']=df['duration'].replace('-','0')
                df['duration'] =df['duration'].astype(float)
                df['missed_bytes']=df['missed_bytes'].replace('-','0')
                df['missed_bytes'] =df['missed_bytes'].astype(int)
                df['orig_pkts']=df['orig_pkts'].replace('-','0')
                df['orig_pkts'] =df['orig_pkts'].astype(int)
                df['orig_ip_bytes']=df['orig_ip_bytes'].replace('-','0')
                df['orig_ip_bytes'] =df['orig_ip_bytes'].astype(int)
                df['proto']=df['proto'].replace('-',np.nan)
                df = df.dropna()

                y_predict = loaded_model.predict(df)
                df_copy['attack'] = y_predict

                records = df_copy.to_dict(orient='records')
                for record in records:
                    if record['attack'] == "DDoS":
                        es.index(index='ddos-alerts', document=record)
                        print("DDoS alert sent to Elasticsearch:", record)
                
                # Save predictions to a CSV file
                df_copy.to_csv('predictions.csv', index=False)  # Change the file path as needed
                
except Exception as e:
    print(f"Error occurred: {e}")
    exit()
