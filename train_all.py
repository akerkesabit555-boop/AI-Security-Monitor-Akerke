import argparse,json
import joblib
from config import DATA,MODELS,OUTPUTS,HTTP_CLASSES
from src.network.preprocess import load_network_csv,clean_network_data
from src.network.models import train_network_models,analyze_network,network_events
from src.nlp.preprocess import load_text_csv,clean_text_data
from src.nlp.models import train_nlp_models,classify_requests,http_events
from src.common.io_utils import save_events
from src.common.metrics import plot_confusion_matrix

def run_network():
    df=clean_network_data(load_network_csv(DATA/'network_traffic.csv')); models,metrics,detail=train_network_models(df)
    for k,m in models.items(): joblib.dump(m,MODELS/f'network_{k}.joblib')
    save_events(network_events(df,analyze_network(df,models)),OUTPUTS/'network_events.csv')
    y,rf,yi,ip=detail; plot_confusion_matrix(y,rf,sorted(y.unique()),OUTPUTS/'reports/cm_network_rf.png'); plot_confusion_matrix(yi,ip,['Normal','Attack'],OUTPUTS/'reports/cm_network_if.png')
    return metrics

def run_nlp():
    df=clean_text_data(load_text_csv(DATA/'http_requests.csv')); models,metrics,detail=train_nlp_models(df)
    for k,m in models.items(): joblib.dump(m,MODELS/f'http_{k}.joblib')
    save_events(http_events(df,classify_requests(df['request'],models['logreg'])),OUTPUTS/'http_events.csv')
    y,pred=detail; plot_confusion_matrix(y,pred,HTTP_CLASSES,OUTPUTS/'reports/cm_http.png')
    return metrics

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--only',choices=['network','nlp']); args=parser.parse_args()
    MODELS.mkdir(exist_ok=True); (OUTPUTS/'reports').mkdir(parents=True,exist_ok=True)
    path=OUTPUTS/'reports/metrics.json'; all_metrics=json.loads(path.read_text()) if path.exists() else {}
    if args.only!='nlp': all_metrics['network']=run_network()
    if args.only!='network': all_metrics['nlp']=run_nlp()
    path.write_text(json.dumps(all_metrics,ensure_ascii=False,indent=2)); print(json.dumps(all_metrics,ensure_ascii=False,indent=2))
if __name__=='__main__': main()
