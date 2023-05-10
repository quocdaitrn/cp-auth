wire:
	wire ./infra/app/

proto:
	rm -f proto/pb/*.go
	protoc --proto_path=proto --go_out=proto/pb --go_opt=paths=source_relative \
	--go-grpc_out=proto/pb --go-grpc_opt=paths=source_relative \
	proto/*.proto

mock:
	./scripts/generate_mock.sh

.PHONY: wire proto mock
