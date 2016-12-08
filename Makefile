CWD := $(shell pwd)

.PHONY : run venv test service start-service stop-service restart-service outputs clean

all:	test run

run:
	python -mSimpleHTTPServer

test:	venv
	. venv/bin/activate && ./tests.py -bv

venv:	venv/bin/activate

venv/bin/activate: requirements.txt
	test -d venv || virtualenv venv
	. venv/bin/activate; env | grep VIRTUAL; pip install -r requirements.txt

service:	venv
	. venv/bin/activate; FLASK_APP=solution/app.py flask run

solution-service:	venv
	. venv/bin/activate; FLASK_APP=SOLUTION_DO_NOT_PEEK/app.py flask run

celery:	venv
	. venv/bin/activate; celery -A solution.tasks worker --loglevel=debug

solution-celery:	venv
	. venv/bin/activate; celery -A SOLUTION_DO_NOT_PEEK.tasks worker --loglevel=debug

v3-database:	venv
	. venv/bin/activate; python solution/models.py

clean:
	rm -rf venv
