# Projeto traefikAI
Projeto de pesquisa 2024/2025 (UFRPE)

(em desenvolvimento)

## Descrição

O projeto traefikAI visa a criação de um 
sistema de detecção de intrusão, utilizando aprendizado de máquina, que possa ser 
utilizado em conjunto com o sistema de proxy 
reverso **Traefik**. 
O sistema de inteligência artificial será 
responsável por analisar o tráfego de rede que chega
ao proxy reverso, através
dos 'logs', e identificar possíveis tentativas de 
ataques. 

## Análise de Dados

A análise de dados será realizada para fins de comparação
entre as ferramentas de detecção de intrusão **Suricata** 
e o modelo obtido através dos 'logs' do **traefik**. 

## Dataset

O dataset utilizado para treinamento do modelo de inteligência artificial será o [TRAEFIK/UFCA 2024](https://www.kaggle.com/datasets/rafaelpbmota/sci01-traefik-semanal).

## Equipe
Rafael Perazzo Barbosa Mota (DC/UFRPE)

## Algoritmos

Os algoritmos de inteligência artificial que serão utilizados no projeto são:
- Árvore de Decisão
- Random Forest
- SVM
- Redes Neurais
- K-means
- KNN

## Tecnologias

As tecnologias utilizadas no projeto serão:

- Python
- Pandas
- Numpy
- Scikit-learn
- TensorFlow
- Keras
- Matplotlib
- Jupiter Notebook

## Licença

GPL-3.0

## Como preparar o ambiente

- Python 3.12
```bash
python3.12 -m venv python312
source python312/bin/activate
pip install -r requirements.txt
```

