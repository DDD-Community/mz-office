FROM python:3.11

# Configure python
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONUNBUFFERED=1


WORKDIR /app

COPY ./requirements.txt /app/requirements.txt

RUN pip install --upgrade pip \
    && pip install --no-cache-dir --upgrade -r /app/requirements.txt


EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]