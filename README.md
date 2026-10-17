# AI Security Monitor — учебный прототип

Система анализа CSV с сетевыми потоками и HTTP-запросами. **Это офлайн-демонстрация, не production IDS/WAF.** Все прогнозы неподтверждённые.

## Запуск

Python 3.11+:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python scripts/generate_network_data.py
python scripts/prepare_text_dataset.py --add-timestamps
python train_all.py
pytest -q
streamlit run app.py --server.address 127.0.0.1
```

Откройте http://127.0.0.1:8501. Генераторы создают **синтетические учебные данные**, а не настоящие журналы атак. Для оценки на внешних данных используйте открытые наборы из ТЗ и `python scripts/prepare_text_dataset.py --sqli PATH --xss PATH`.

## Структура

- `config.py` — контракт и признаки.
- `src/network` — предобработка, Isolation Forest, Random Forest.
- `src/nlp` — URL/HTML нормализация, TF-IDF, Logistic Regression, Naive Bayes.
- `src/common` — CSV, метрики, события.
- `train_all.py` — обучение, метрики и экспорт событий.
- `app.py` — пять вкладок Streamlit.
- `outputs/reports` — матрицы ошибок и metrics.json после обучения.

## Ограничения

Синтетические шаблоны в HTTP-наборе повторяются и могут завышать качество. Для честного исследования используйте независимые открытые данные и ручную проверку ложных срабатываний. Не загружайте чужие `.joblib` — они используют pickle. Система не выполняет HTTP-запросы и не сканирует сеть.
