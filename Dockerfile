FROM python:2-alpine

ENV app /app

RUN mkdir $app
WORKDIR $app
COPY requirements.txt $app

RUN pip install -r requirements.txt

COPY . $app

WORKDIR API/

EXPOSE 8094
ENTRYPOINT ["python", "./api.py"]
CMD ["tail -f /app/logs/scan.log"]
