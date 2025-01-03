all: build-docker upload-docker

build-docker:
	docker build -t netwatch_ssh-attackpod:latest -t netwatch_ssh-attackpod:8.2 .

upload-docker:
	docker push netwatch_ssh-attackpod:latest
