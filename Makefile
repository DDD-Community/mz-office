shell:
	docker-compose run --service-ports app bash

shell-redis:
	docker-compose exec redis redis-cli

shell-mysql:
	docker-compose exec mysql mysql -uroot -proot

build: clean
	docker-compose build

up:
	docker-compose up -d --build

logs:
	docker-compose logs -f

down:
	docker-compose down --remove-orphans

clean: down
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +
