# lab-ctf-decouverte-m1 — orchestration du lab.
#
# Cibles : up / down / rebuild / logs / test / test-chain / ps / clean
SHELL := /bin/bash
# Auto-détection : `docker compose` (v2) sinon `docker-compose` (v1).
COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

.DEFAULT_GOAL := help

.PHONY: help env host-setup up down rebuild logs ps test test-chain clean

help: ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

env: ## Crée .env depuis .env.example s'il manque
	@test -f .env || { cp .env.example .env; echo "[.env] créé depuis .env.example"; }

host-setup: ## Pré-requis réseau de l'hôte (bridge-nf), idempotent — root requis
	@sudo -n true 2>/dev/null && sudo ./scripts/host-net.sh || ./scripts/host-net.sh

up: env host-setup ## Build + démarre toute l'infra
	$(COMPOSE) up -d --build
	@echo
	@echo ">> Point d'entrée étudiants : http://$$(grep -E '^WEB_PUBLISH_IP=' .env | cut -d= -f2):$$(grep -E '^WEB_PUBLISH_PORT=' .env | cut -d= -f2)"

down: ## Arrête et supprime conteneurs + réseaux
	$(COMPOSE) down

rebuild: ## Rebuild complet sans cache puis redémarre
	$(COMPOSE) build --no-cache
	$(COMPOSE) up -d

logs: ## Suit les logs de tous les services (Ctrl-C pour quitter)
	$(COMPOSE) logs -f

ps: ## État des conteneurs
	$(COMPOSE) ps

test: ## Critères d'acceptation réseau (verify-firewall.sh)
	@./scripts/verify-firewall.sh

test-chain: ## Test fonctionnel de toute la chaîne d'attaque (verify-chain.sh)
	@./scripts/verify-chain.sh

clean: ## down + purge images du lab + volumes anonymes
	$(COMPOSE) down --rmi local -v --remove-orphans
