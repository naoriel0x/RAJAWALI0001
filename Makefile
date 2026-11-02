
.PHONY: up down restart logs build clean dev

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f

build:
	docker compose build --no-cache

clean:
	docker compose down -v --remove-orphans

dev:
	docker compose up

status:
	docker compose ps

shell-backend:
	docker compose exec backend bash

shell-db:
	docker compose exec postgres psql -U rajawali