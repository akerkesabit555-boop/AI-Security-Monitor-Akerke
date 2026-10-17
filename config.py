from pathlib import Path
ROOT=Path(__file__).resolve().parent
DATA=ROOT/'data'; MODELS=ROOT/'models'; OUTPUTS=ROOT/'outputs'
RANDOM_STATE=42
NETWORK_FEATURES=['Destination Port','Flow Duration','Total Fwd Packets','Total Backward Packets','Total Length of Fwd Packets','Total Length of Bwd Packets','Fwd Packet Length Mean','Bwd Packet Length Mean','Flow Bytes/s','Flow Packets/s','Flow IAT Mean','SYN Flag Count','ACK Flag Count','Average Packet Size']
HTTP_CLASSES=['Normal','SQL Injection','XSS']
EVENT_COLUMNS=['event_id','timestamp','source_module','model_name','prediction','score','is_alert','needs_review','ground_truth','details','status']
STATUS='Прогноз модели (не подтверждено)'
MAX_BYTES=20*1024*1024; MAX_ROWS=200000
