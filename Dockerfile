#
# NOTE: THIS DOCKERFILE IS GENERATED VIA "apply-templates.sh"
#
# PLEASE DO NOT EDIT IT DIRECTLY.
#

# Use Python 3.12 slim image
FROM mcr.microsoft.com/playwright/python:v1.54.0-noble

# ENV variables

# Django core settings
ARG SECRET_KEY
ARG DEBUG
ARG HOST
ARG ALLOWED_HOSTS
ARG PAGE_SIZE
ARG TEST_HEADLESS

# CORS / CSRF settings (optional)
ARG CORS_ALLOWED_ORIGINS
ARG CSRF_TRUSTED_ORIGINS

# Storage
ARG STORAGE_AWS
ARG AWS_ACCESS_KEY_ID
ARG AWS_SECRET_ACCESS_KEY
ARG AWS_STORAGE_BUCKET_NAME

# Database
ARG DB_ENGINE
ARG DB_NAME
ARG DB_USER
ARG DB_PASSWORD
ARG DB_HOST
ARG DB_PORT

# Django core settings
ENV SECRET_KEY=${SECRET_KEY}
ENV DEBUG=${DEBUG}
ENV HOST=${HOST}
ENV ALLOWED_HOSTS=${ALLOWED_HOSTS}
ENV PAGE_SIZE=${PAGE_SIZE}
ENV TEST_HEADLESS=${TEST_HEADLESS}

# CORS / CSRF settings (optional)
ENV CORS_ALLOWED_ORIGINS=${CORS_ALLOWED_ORIGINS}
ENV CSRF_TRUSTED_ORIGINS=${CSRF_TRUSTED_ORIGINS}

# Storage
ENV STORAGE_AWS=${STORAGE_AWS}
ENV AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
ENV AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
ENV AWS_STORAGE_BUCKET_NAME=${AWS_STORAGE_BUCKET_NAME}

# Database
ENV DB_ENGINE=${DB_ENGINE}
ENV DB_NAME=${DB_NAME}
ENV DB_USER=${DB_USER}
ENV DB_PASSWORD=${DB_PASSWORD}
ENV DB_HOST=${DB_HOST}
ENV DB_PORT=${DB_PORT}

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container
COPY . /app/

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpq-dev gcc \
    curl \
    wget \
    gnupg \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Install Playwright browsers
RUN python -m playwright install


# Collect static files and migrate database
RUN python manage.py collectstatic --noinput
RUN python manage.py makemigrations
RUN python manage.py migrate
RUN python manage.py apps_loaddata

# Expose the port that Django/Gunicorn will run on
EXPOSE 80

# Command to run Gunicorn with the WSGI application for production
CMD ["gunicorn", "--bind", "0.0.0.0:80", "project.wsgi:application"]