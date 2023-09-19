start:
	docker compose down && docker compose up -d

start-rebuild:
	docker compose down && docker compose up -d --build

stop:
	docker compose down

rm-docker-volume:
	docker compose down --volumes
