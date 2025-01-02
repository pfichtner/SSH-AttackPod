all: build-docker upload-docker

build-docker:
	docker build -t docker.k0nig.de/netwatch_ssh_attack_pod:9.9 .

upload-docker:
	docker push docker.k0nig.de/netwatch_ssh_attack_pod:9.9
