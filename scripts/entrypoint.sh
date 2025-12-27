#!/bin/bash
set -e 

python3 manage.py makemigrations && \
python3 manage.py makemigrations StaticAnalyzer && \
python3 manage.py migrate
set +e
python3 manage.py createsuperuser --noinput --email ""
set -e
python3 manage.py create_roles

# Test that the WSGI application can be imported before starting gunicorn
echo "Testing WSGI application import..."
python3 -c "from mobsf.MobSF.wsgi import application; print('WSGI application imported successfully')"

# Start gunicorn with more verbose logging - Cyberspect modified readability
exec gunicorn -b 0.0.0.0:8000 "mobsf.MobSF.wsgi:application" \
    --workers=1 \
    --threads=10 \
    --timeout=3600 \
    --worker-tmp-dir=/dev/shm \
    --log-level=critical \
    --log-file=- \
    --access-logfile=- \
    --error-logfile=- \
    --capture-output
    