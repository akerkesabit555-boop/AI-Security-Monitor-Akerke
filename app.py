import json
import joblib
import pandas as pd
import streamlit as st
from config import MODELS,OUTPUTS,NETWORK_FEATURES,STATUS
from src.common.io_utils import read_csv_safely,require_columns,load_events,to_csv_bytes,data_quality_report
from src.network.preprocess import clean_network_data
from src.network.models import analyze_network,network_events
from src.nlp.models import classify_requests,explain_request,http_events
st.set_page_config(page_title='AI Security Monitor',page_icon='🛡️',layout='wide')
st.title('🛡️ AI Security Monitor')
st.caption('Учебная система. Все результаты: '+STATUS+'. Не используйте как единственную защиту.')
@st.cache_resource
def model(name):
    path=MODELS/name
    if not path.exists(): raise FileNotFoundError('Сначала выполните python train_all.py')
    return joblib.load(path)
@st.cache_data
def original_events():
    parts=[load_events(OUTPUTS/f'{m}_events.csv') for m in ['network','http'] if (OUTPUTS/f'{m}_events.csv').exists()]
    return pd.concat(parts,ignore_index=True) if parts else pd.DataFrame()
if 'network_events' not in st.session_state: st.session_state.network_events=None
if 'http_events' not in st.session_state: st.session_state.http_events=None
parts=[]
for name in ['network','http']:
    replacement=st.session_state[f'{name}_events']
    if replacement is not None: parts.append(replacement)
    elif not original_events().empty: parts.append(original_events()[original_events().source_module==name])
events=pd.concat(parts,ignore_index=True) if parts else pd.DataFrame()
tabs=st.tabs(['Обзор','Сетевой трафик','HTTP-запросы','Качество моделей','О системе'])
with tabs[0]:
    if events.empty: st.warning('Нет событий. Выполните python train_all.py')
    else:
        f1,f2,f3,f4=st.columns(4)
        module=f1.multiselect('Модуль',sorted(events.source_module.unique()))
        category=f2.multiselect('Категория',sorted(events.prediction.unique()))
        alert=f3.selectbox('Результат',['Все','Тревога','Без тревоги','Требует проверки'])
        start=f4.date_input('Дата от',value=None)
        d=events.copy()
        if module:d=d[d.source_module.isin(module)]
        if category:d=d[d.prediction.isin(category)]
        if alert=='Тревога':d=d[d.is_alert]
        elif alert=='Без тревоги':d=d[~d.is_alert]
        elif alert=='Требует проверки':d=d[d.needs_review]
        if start is not None: d=d[pd.to_datetime(d.timestamp,errors='coerce').dt.date>=start]
        k=st.columns(5)
        for col,(name,value) in zip(k,[('Всего',len(d)),('Тревоги',int(d.is_alert.sum())),('Норма',int((~d.is_alert).sum())),('На проверку',int(d.needs_review.sum())),('Доля тревог',f'{d.is_alert.mean():.1%}' if len(d) else '0%')]):col.metric(name,value)
        st.subheader('Категории'); st.bar_chart(d.prediction.value_counts())
        st.subheader('Модули'); st.bar_chart(d.source_module.value_counts())
        st.dataframe(d,use_container_width=True)
        st.download_button('Скачать события CSV',to_csv_bytes(d),'events.csv','text/csv')
with tabs[1]:
    st.write('Загрузите сетевой CSV (максимум 20 МБ, 200 000 строк).')
    f=st.file_uploader('Сетевые потоки',type=['csv'],key='net')
    if f:
        try:
            d=read_csv_safely(f); require_columns(d,NETWORK_FEATURES); st.json(data_quality_report(d)); d=clean_network_data(d)
            if st.button('Анализировать сеть'):
                m={'iso':model('network_iso.joblib'),'rf':model('network_rf.joblib')}; result=analyze_network(d,m); st.session_state.network_events=network_events(d,result); st.success('Готово. Результаты на вкладке «Обзор».'); st.dataframe(result.head(100))
        except Exception as e:st.error(str(e))
with tabs[2]:
    try:
        m=model('http_logreg.joblib'); query=st.text_area('Один HTTP-запрос','/search?q=python+book')
        if st.button('Проверить запрос'):
            pred=classify_requests([query],m); st.dataframe(pred); st.write('Наиболее влиятельные n-граммы:',explain_request(query,m))
        f=st.file_uploader('CSV со столбцом request',type=['csv'],key='http')
        if f:
            d=read_csv_safely(f);require_columns(d,['request'])
            if st.button('Анализировать HTTP CSV'):
                result=classify_requests(d.request.fillna(''),m); st.session_state.http_events=http_events(d,result); st.dataframe(result.head(100));st.download_button('Скачать HTTP CSV',to_csv_bytes(result),'http_predictions.csv','text/csv')
    except Exception as e:st.error(str(e))
with tabs[3]:
    path=OUTPUTS/'reports/metrics.json'
    if path.exists():st.json(json.loads(path.read_text()))
    for name in ['cm_network_rf.png','cm_network_if.png','cm_http.png']:
        path=OUTPUTS/'reports'/name
        if path.exists():st.image(str(path),caption=name)
with tabs[4]:
    st.markdown('**Модели:** Isolation Forest, Random Forest, TF-IDF + Logistic Regression, Naive Bayes.\n\n**Ограничения:** офлайн-анализ; синтетические данные не отражают качество на реальной сети; прогноз не подтверждает факт атаки.\n\n**Безопасность:** загрузка только CSV, локальные модели, защита CSV-экспорта от формул.')
