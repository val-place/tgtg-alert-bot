env=prod
context=rancher-local
namespace := bots

CHART ?= toogoodtogo-alert-bot
COMMIT_SHA := $(shell git rev-parse HEAD)
SET_ENV := $(shell kubectl config set-context $(context) --namespace=$(namespace))

build:
	docker build -t registry.val.place/toogoodtogo-alert-bot:${COMMIT_SHA} .

push:
	docker push registry.val.place/toogoodtogo-alert-bot:${COMMIT_SHA}

prepare:
	@kubectl config set-context $(context) --namespace=$(namespace)
	@kubectl config use-context $(context)

run:
	./run.sh

deploy: prepare
	cat k8s.yaml | sed 's/IMAGE_TAG/${COMMIT_SHA}/g' | kubectl apply -f -
