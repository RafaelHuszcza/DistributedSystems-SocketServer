# Dockerfile

# Use uma imagem base com Python
FROM python:3.10-slim-bullseye

# Defina o diretório de trabalho
WORKDIR /usr/src/app

# Copie o arquivo de requisitos e os arquivos do projeto para o diretório de trabalho
COPY requirements.txt ./
COPY . .

# Instale as dependências do projeto
RUN pip install --no-cache-dir -r requirements.txt

# Exponha as portas nas quais o servidor estará disponível
EXPOSE 8000

# Comando para iniciar o servidor
CMD ["python", "main.py"]
